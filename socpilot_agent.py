#!/usr/bin/env python3
import csv
import hashlib
import html
import io
import json
import os
import re
import sqlite3
import httpx
import sys
import webbrowser
import shlex
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

HOST = "127.0.0.1"
PORT = 8765
DB_PATH = os.path.join(os.path.dirname(__file__), "socpilot.db")

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 95),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), 95),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), 90),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 90),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 90),
    ("OpenAI-like Key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), 85),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"), 100),
]
PRIVATE_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)")
SUSPICIOUS_PROC = ["powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "psexec"]
RANSOM_CMDS = ["vssadmin delete shadows", "wbadmin delete", "bcdedit /set", "cipher /w", "wevtutil cl", "delete shadows"]
DATA_EXT = [".zip", ".7z", ".rar", ".sql", ".bak", ".dump", ".csv", ".xlsx"]
ADMIN_WORDS = ["admin", "administrator", "root", "svc_", "service", "domain admin"]

PLAYBOOKS = {
    "ransomware": {"name": "랜섬웨어 의심 초동대응", "goal": "확산 차단, 증거 보존, 백업 영향 확인", "mitre": ["T1059 Command and Scripting Interpreter", "T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery"]},
    "malware": {"name": "악성코드 감염 초동대응", "goal": "감염 단말 격리, 프로세스/파일/네트워크 증거 확보", "mitre": ["T1204 User Execution", "T1059 Command and Scripting Interpreter", "T1105 Ingress Tool Transfer"]},
    "bruteforce": {"name": "계정 무차별 대입 대응", "goal": "계정 보호, 공격 IP 차단, 인증 로그 확인", "mitre": ["T1110 Brute Force", "T1078 Valid Accounts"]},
    "exfiltration": {"name": "데이터 반출 의심 대응", "goal": "반출 경로 차단, 전송량 확인, 민감 데이터 범위 산정", "mitre": ["T1041 Exfiltration Over C2 Channel", "T1567 Exfiltration Over Web Service"]},
    "secret_leak": {"name": "Secret/API Key 유출 대응", "goal": "노출 키 폐기, 권한 검토, 사용 이력 조사", "mitre": ["T1552 Unsecured Credentials", "T1528 Steal Application Access Token"]},
    "phishing": {"name": "피싱 클릭/계정 입력 대응", "goal": "계정 탈취 차단, URL 차단, 유사 수신자 확인", "mitre": ["T1566 Phishing", "T1204 User Execution", "T1078 Valid Accounts"]},
    "generic": {"name": "일반 보안 알림 분류", "goal": "오탐 여부 판단, 원본 로그 확보, 자산 중요도 확인", "mitre": ["T1082 System Information Discovery"]},
}

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_db():
    con = sqlite3.connect(DB_PATH, timeout=15.0)
    con.execute("PRAGMA journal_mode=WAL;")
    return con

def init_db():
    con = get_db()
    cur = con.cursor()
    def table_cols(name):
        cur.execute(f"pragma table_info({name})")
        return [r[1] for r in cur.fetchall()]
    expected_incidents = ["id", "created_at", "title", "severity", "score", "playbook", "status", "host", "user", "src_ip", "dst_ip", "alert_json", "result_json"]
    expected_actions = ["id", "incident_id", "phase", "action", "command", "owner", "status", "created_at"]
    if table_cols("incidents") and table_cols("incidents") != expected_incidents:
        cur.execute("alter table incidents rename to incidents_backup_" + datetime.now().strftime("%Y%m%d%H%M%S"))
    if table_cols("actions") and table_cols("actions") != expected_actions:
        cur.execute("alter table actions rename to actions_backup_" + datetime.now().strftime("%Y%m%d%H%M%S"))
    cur.execute("""create table if not exists incidents(
        id text primary key, created_at text, title text, severity text, score integer,
        playbook text, status text, host text, user text, src_ip text, dst_ip text,
        alert_json text, result_json text)""")
    cur.execute("""create table if not exists actions(
        id integer primary key autoincrement, incident_id text, phase text, action text,
        command text, owner text, status text, created_at text)""")
    con.commit(); con.close()

def safe_int(v, default=0):
    try:
        if v is None or str(v).strip() == "": return default
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default

def boolish(v):
    return str(v).strip().lower() in {"1", "true", "yes", "y", "clicked", "opened"}

def public_ip(ip):
    ip = str(ip or "").strip()
    if not ip or PRIVATE_IP.match(ip): return False
    parts = ip.split(".")
    if len(parts) != 4: return False
    try:
        return all(0 <= int(x) <= 255 for x in parts)
    except Exception:
        return False

def clean(v):
    return str(v or "").replace("`", "'").replace("\n", " ").strip()

def add(ev, score, text):
    ev.append({"score": int(score), "text": text})

def classify(alert):
    blob = " ".join(str(alert.get(k, "")) for k in alert).lower()
    alert_type = str(alert.get("alert_type", "")).lower()
    process = str(alert.get("process", "")).lower()
    cmd = str(alert.get("command_line", "")).lower()
    user = str(alert.get("user", ""))
    src_ip = str(alert.get("src_ip", ""))
    dst_ip = str(alert.get("dst_ip", ""))
    bytes_out = safe_int(alert.get("bytes_out"))
    failed = safe_int(alert.get("failed_count"))
    clicked = boolish(alert.get("clicked"))
    credentials = boolish(alert.get("credentials_entered"))
    file_path = str(alert.get("file_path", "")).lower()
    url = str(alert.get("url", ""))
    scores = {k: 0 for k in PLAYBOOKS}
    scores["generic"] = 5
    evidence = []

    explicit_type = ""
    if "ransom" in alert_type: explicit_type = "ransomware"
    elif "data_exfil" in alert_type or "exfil" in alert_type: explicit_type = "exfiltration"
    elif "secret" in alert_type or "token" in alert_type or "credential" in alert_type: explicit_type = "secret_leak"
    elif "phish" in alert_type: explicit_type = "phishing"
    elif "brute" in alert_type or "login_failed" in alert_type: explicit_type = "bruteforce"
    elif "malware" in alert_type or "edr" in alert_type: explicit_type = "malware"

    if "ransom" in alert_type or any(x in cmd for x in RANSOM_CMDS):
        scores["ransomware"] += 70; add(evidence, 70, "섀도 복사본 삭제/복구 방해 등 랜섬웨어 전형 명령 탐지")
    if any(p in process for p in SUSPICIOUS_PROC) or any(p in cmd for p in SUSPICIOUS_PROC):
        scores["malware"] += 18; add(evidence, 18, "스크립트/LOLBins 계열 의심 프로세스 사용")
    if "encodedcommand" in cmd or "frombase64string" in cmd or "downloadstring" in cmd:
        scores["malware"] += 30; add(evidence, 30, "난독화 또는 원격 다운로드 PowerShell 패턴")
    if "malware" in alert_type or "edr" in alert_type:
        scores["malware"] += 25; add(evidence, 25, "EDR/악성코드 유형 알림")
    if failed >= 20 or "brute" in alert_type or "login_failed" in alert_type:
        s = min(58, 20 + failed // 2); scores["bruteforce"] += s; add(evidence, s, f"로그인 실패 횟수 과다: {failed}회")
    if public_ip(src_ip) and failed >= 10:
        scores["bruteforce"] += 15; add(evidence, 15, "외부 IP에서 반복 로그인 시도")
    if any(w in user.lower() for w in ADMIN_WORDS) and (failed or "login" in alert_type):
        scores["bruteforce"] += 18; add(evidence, 18, "관리자/서비스 계정 대상 인증 이벤트")
    if bytes_out >= 500_000_000:
        scores["exfiltration"] += 50; add(evidence, 50, f"대용량 외부 전송: {bytes_out:,} bytes")
    elif bytes_out >= 100_000_000:
        scores["exfiltration"] += 30; add(evidence, 30, f"비정상적으로 큰 외부 전송: {bytes_out:,} bytes")
    if public_ip(dst_ip) and bytes_out >= 50_000_000:
        scores["exfiltration"] += 18; add(evidence, 18, "외부 목적지로 대용량 전송")
    if any(file_path.endswith(ext) for ext in DATA_EXT) and bytes_out >= 20_000_000:
        scores["exfiltration"] += 16; add(evidence, 16, "압축/DB/CSV 파일 반출 가능성")
    for name, rx, s in SECRET_PATTERNS:
        if rx.search(blob):
            scores["secret_leak"] += s; add(evidence, s, f"{name} 형태의 Secret 노출")
    if "secret" in alert_type or "token" in alert_type or "credential" in alert_type:
        scores["secret_leak"] += 25; add(evidence, 25, "Secret/Credential 유형 알림")
    if "phish" in alert_type or clicked or credentials or url:
        scores["phishing"] += 20; add(evidence, 20, "URL/피싱 관련 신고 또는 클릭 이벤트")
    if credentials:
        scores["phishing"] += 55; add(evidence, 55, "사용자가 계정정보를 입력한 것으로 표시됨")
    if clicked:
        scores["phishing"] += 20; add(evidence, 20, "사용자가 링크를 클릭한 것으로 표시됨")
    if not evidence:
        add(evidence, 5, "명확한 고위험 신호는 낮음. 원본 로그 추가 확인 필요")

    if explicit_type and scores.get(explicit_type, 0) >= 25:
        scores[explicit_type] += 18
    playbook = max(scores, key=scores.get)
    score = min(100, max(scores[playbook], sum(x["score"] for x in evidence) // 2))
    if score >= 85: severity = "P1 Critical"
    elif score >= 65: severity = "P2 High"
    elif score >= 35: severity = "P3 Medium"
    else: severity = "P4 Low"
    return playbook, score, severity, sorted(evidence, key=lambda x: x["score"], reverse=True)

def get_ai_client(api_key):
    if not OpenAI or not api_key:
        return None
    api_key = api_key.strip()
    if not api_key.startswith("sk-"):
        return OpenAI(api_key=api_key, base_url="https://factchat-cloud.mindlogic.ai/v1/gateway", http_client=httpx.Client(verify=False))
    return OpenAI(api_key=api_key)

def classify_ai(alert, api_key):
    client = get_ai_client(api_key)
    if not client:
        return classify(alert)
    try:
        prompt = f"다음 보안 로그를 분석해서 JSON으로만 답해라. 분류(playbook)는 ransomware, malware, bruteforce, exfiltration, secret_leak, phishing, generic 중 하나다.\n로그: {json.dumps(alert, ensure_ascii=False)}"
        res = client.chat.completions.create(
            model="gpt-4o-mini" if api_key.startswith("sk-") else "claude-sonnet-4-6",
            messages=[
                {"role": "system", "content": "너는 1차 SOC 분석 AI다. 출력은 오직 순수한 JSON 형식 {\"playbook\": \"malware\", \"score\": 85, \"severity\": \"P1 Critical\", \"evidence\": [{\"score\": 85, \"text\": \"이유\"}]} 이것만 뱉어라."},
                {"role": "user", "content": prompt}
            ]
        )
        raw_content = res.choices[0].message.content.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:-3].strip()
        elif raw_content.startswith("```"):
            raw_content = raw_content[3:-3].strip()
        data = json.loads(raw_content)
        return data.get("playbook", "generic"), int(data.get("score", 0)), data.get("severity", "P4 Low"), data.get("evidence", [])
    except Exception as e:
        print(f"1차 AI 에러: {e}")
        return classify(alert)

def verify_ai(alert, playbook, score, evidence, api_key):
    client = get_ai_client(api_key)
    if not client:
        raise Exception("API Key가 없어서 제3자 검증을 수행할 수 없습니다.")
    try:
        prompt = f"원본 로그: {json.dumps(alert, ensure_ascii=False)}\n1차 AI 판단 결과: 분류={playbook}, 위험도 점수={score}점\n1차 AI 주요 근거: {evidence}\n\n위 1차 분석 결과가 논리적으로 타당한지 교차 검증하고 JSON으로만 답해라. (과잉 탐지, 오탐 여부 확인)"
        res = client.chat.completions.create(
            model="gpt-4o-mini" if api_key.startswith("sk-") else "claude-sonnet-4-6",
            messages=[
                {"role": "system", "content": "너는 제3자 검증을 수행하는 수석 감사(Auditor) AI다. 1차 AI가 환각을 일으켰는지 비판적으로 검토해라. 동의하면 agree에 true, 틀렸다면 false를 넣고 신뢰도(1~100)와 검증 사유를 작성해라. 출력 형식: {\"agree\": true, \"confidence\": 95, \"reason\": \"이유 상세 기술\"}"},
                {"role": "user", "content": prompt}
            ]
        )
        raw_content = res.choices[0].message.content.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:-3].strip()
        elif raw_content.startswith("```"):
            raw_content = raw_content[3:-3].strip()
        data = json.loads(raw_content)
        return {
            "agree": data.get("agree", True),
            "confidence": data.get("confidence", 90),
            "reason": data.get("reason", "검증 완료")
        }
    except Exception as e:
        raise Exception(f"제3자 검증 중 AI 에러: {e}")

def generate_actions(alert, playbook):
    host = shlex.quote(clean(alert.get("host")) or "<HOST>")
    user = shlex.quote(clean(alert.get("user")) or "<USER>")
    src_ip = shlex.quote(clean(alert.get("src_ip")) or "<SRC_IP>")
    dst_ip = shlex.quote(clean(alert.get("dst_ip")) or "<DST_IP>")
    process = shlex.quote(clean(alert.get("process")) or "<PROCESS>")
    url = shlex.quote(clean(alert.get("url")) or "<URL>")
    
    actions = []
    def a(phase, action, command, owner="SOC"):
        actions.append({"phase": phase, "action": action, "command": command, "owner": owner, "status": "대기"})
    if playbook == "ransomware":
        a("Containment", "EDR로 단말 네트워크 격리", f"EDR isolate-host --host {host}", "SOC/EDR")
        a("Recovery", "백업 상태와 암호화 범위 확인", "backupctl job list --last 24h", "Infra")
    elif playbook == "malware":
        a("Containment", "감염 의심 호스트 격리", f"EDR isolate-host --host {host}", "SOC/EDR")
        a("Eradication", "의심 프로세스 강제 종료", f"taskkill /S {host} /IM {process} /F", "IR")
    elif playbook == "bruteforce":
        a("Containment", "공격 출발지 IP 방화벽 차단", f"firewall block ip {src_ip}", "Network")
        a("Containment", "대상 계정 임시 잠금", f"Disable-ADAccount -Identity {user}", "IAM")
    elif playbook == "exfiltration":
        a("Containment", "목적지 IP 통신 차단", f"firewall block ip {dst_ip}", "Network")
        a("Investigation", "전송량 타임라인 분석", f"SIEM search host={host} user={user} | stats sum(bytes_out)", "SOC")
    elif playbook == "secret_leak":
        a("Containment", "노출 Secret 즉시 폐기", "secret-manager rotate --secret '<SECRET_NAME>'", "DevOps")
    elif playbook == "phishing":
        a("Containment", "피싱 URL Proxy 차단", f"proxy block-url {url}", "Network")
        a("Containment", "계정 세션 강제 종료", f"Revoke-UserSession -User {user}", "IAM")
    else:
        a("Triage", "자산 소유자에게 징후 통보", f"notify-owner --host {host}", "SOC")
    return actions

def build_result(alert, api_key):
    playbook, score, severity, evidence = classify_ai(alert, api_key)
    pb = PLAYBOOKS.get(playbook, PLAYBOOKS["generic"])
    title = f"{pb['name']} - {alert.get('host') or alert.get('user') or alert.get('src_ip') or 'unknown'}"
    
    if not evidence:
        evidence = [{"score": score, "text": "분석 엔진 평가 완료"}]
        
    summary = f"{severity} / {score}점. '{pb['name']}'로 분류됨. 목표: {pb['goal']}."

    return {
        "playbook": playbook, "playbook_name": pb["name"], "goal": pb["goal"], "mitre": pb["mitre"],
        "score": score, "severity": severity, "title": title, "evidence": evidence,
        "actions": generate_actions(alert, playbook), "executive_summary": summary,
        "verification": {} 
    }

def new_id(alert):
    raw = json.dumps(alert, sort_keys=True, ensure_ascii=False) + datetime.now().strftime("%Y%m%d%H%M%S%f")
    return "INC-" + datetime.now().strftime("%Y%m%d") + "-" + hashlib.sha1(raw.encode()).hexdigest()[:6].upper()

def save_incident(alert, result):
    iid = new_id(alert)
    con = get_db()
    try:
        cur = con.cursor()
        cur.execute("insert into incidents values(?,?,?,?,?,?,?,?,?,?,?,?,?)", (iid, now(), result["title"], result["severity"], result["score"], result["playbook"], "Open", str(alert.get("host", "")), str(alert.get("user", "")), str(alert.get("src_ip", "")), str(alert.get("dst_ip", "")), json.dumps(alert, ensure_ascii=False), json.dumps(result, ensure_ascii=False)))
        for a in result["actions"]:
            cur.execute("insert into actions(incident_id,phase,action,command,owner,status,created_at) values(?,?,?,?,?,?,?)", (iid, a["phase"], a["action"], a["command"], a["owner"], a["status"], now()))
        con.commit()
    finally:
        con.close()
    return iid

def rows(sql, args=()):
    con = get_db()
    con.row_factory = sqlite3.Row
    out = [dict(r) for r in con.execute(sql, args).fetchall()]
    con.close(); return out

def list_incidents():
    return rows("select * from incidents order by created_at desc limit 200")

def get_incident(iid):
    incs = rows("select * from incidents where id=?", (iid,))
    if not incs: return None
    inc = incs[0]
    inc["alert"] = json.loads(inc.pop("alert_json"))
    inc["result"] = json.loads(inc.pop("result_json"))
    inc["actions"] = rows("select * from actions where incident_id=? order by id", (iid,))
    return inc

def set_action_status(action_id, status):
    con = get_db()
    con.execute("update actions set status=? where id=?", (status, action_id))
    con.commit(); con.close()

def import_csv_text(text, api_key):
    items = []
    agg_data = {}

    for row in csv.DictReader(io.StringIO(text)):
        try:
            alert_type = str(row.get("alert_type", "")).strip()
            src_ip = str(row.get("src_ip", "")).strip()
            dst_ip = str(row.get("dst_ip", "")).strip()
            host = str(row.get("host", "")).strip()
            user = str(row.get("user", "")).strip()

            key = f"{alert_type}_{src_ip}_{dst_ip}_{host}_{user}"

            if key not in agg_data:
                agg_data[key] = {k: v for k, v in row.items() if k}
                agg_data[key]["failed_count"] = safe_int(row.get("failed_count"))
                agg_data[key]["bytes_out"] = safe_int(row.get("bytes_out"))
                agg_data[key]["clicked"] = boolish(row.get("clicked"))
                agg_data[key]["credentials_entered"] = boolish(row.get("credentials_entered"))
                agg_data[key]["agg_count"] = 1
            else:
                agg_data[key]["failed_count"] += safe_int(row.get("failed_count"))
                agg_data[key]["bytes_out"] += safe_int(row.get("bytes_out"))
                agg_data[key]["agg_count"] += 1
                if boolish(row.get("clicked")): agg_data[key]["clicked"] = True
                if boolish(row.get("credentials_entered")): agg_data[key]["credentials_entered"] = True
        except Exception as e:
            continue

    for key, alert in agg_data.items():
        try:
            if alert["agg_count"] > 1:
                alert["command_line"] = str(alert.get("command_line", "")) + f" [자동 병합됨: 단기간 {alert['agg_count']}회 반복 공격]"
            result = build_result(alert, api_key)
            iid = save_incident(alert, result)
            items.append({"id": iid, "severity": result["severity"], "score": result["score"], "playbook": result["playbook_name"], "title": result["title"]})
        except Exception as e:
            continue
    return items

def report_text(iid):
    inc = get_incident(iid)
    if not inc: return "Not found"
    r = inc["result"]
    ver = r.get("verification", {})
    lines = ["# SOC Pilot Agent Incident Report", "", f"- Incident ID: {inc['id']}", f"- Severity: {inc['severity']}", f"- Score: {inc['score']}/100", f"- Playbook: {r['playbook_name']}", "", "## 제3자 AI 검증 (Auditor Review)"]
    if ver and "agree" in ver:
        lines += [f"- **검증 동의 여부**: {'동의 (Agree)' if ver.get('agree') else '불일치 (Disagree)'}"]
        lines += [f"- **신뢰도 (Confidence)**: {ver.get('confidence')}%"]
        lines += [f"- **사유**: {ver.get('reason')}"]
    else:
        lines += ["- **상태**: 2차 교차 검증 미수행"]
    lines += ["", "## Executive Summary", r["executive_summary"], "", "## MITRE ATT&CK Mapping"]
    lines += [f"- {m}" for m in r["mitre"]]
    lines += ["", "## Evidence"]
    lines += [f"- [{e['score']}점] {e['text']}" for e in r["evidence"]]
    lines += ["", "## Response Actions"]
    lines += [f"- [{a['status']}] {a['phase']} / {a['action']} / `{a['command']}`" for a in inc["actions"]]
    return "\n".join(lines)

HTML = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SOC Pilot Agent</title><style>
:root{--bg:#0b1020;--panel:#111a2e;--panel2:#16213a;--text:#e8eefc;--muted:#9fb0d0;--blue:#58a6ff;--red:#ff5c7a;--orange:#ffb86b;--yellow:#f8e16c;--green:#63e6be;--line:#263755}*{box-sizing:border-box}body{margin:0;font-family:system-ui,Apple SD Gothic Neo,Malgun Gothic,sans-serif;background:linear-gradient(135deg,#07111f,#111827 50%,#0b1020);color:var(--text)}header{padding:20px 32px;border-bottom:1px solid var(--line);background:rgba(10,16,30,.9);position:sticky;top:0;z-index:3;display:flex;justify-content:space-between;align-items:center}h1{margin:0;font-size:28px}.sub{color:var(--muted);margin-top:6px}.wrap{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 90px)}nav{border-right:1px solid var(--line);padding:18px;background:rgba(13,20,36,.7)}nav button{width:100%;margin:6px 0;padding:13px;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:12px;text-align:left;cursor:pointer;font-weight:700}nav button.active{border-color:var(--blue);box-shadow:0 0 0 2px rgba(88,166,255,.15)}main{padding:24px}.card{background:rgba(17,26,46,.95);border:1px solid var(--line);border-radius:18px;padding:20px;margin-bottom:18px;box-shadow:0 10px 30px rgba(0,0,0,.25)}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}label{display:block;color:var(--muted);font-size:13px;margin:9px 0 6px}input,select,textarea{width:100%;background:#0a1222;border:1px solid #2b3d5d;color:var(--text);border-radius:10px;padding:11px;font-family:inherit}textarea{min-height:110px}button.primary{background:linear-gradient(135deg,#1f6feb,#58a6ff);border:0;color:white;padding:12px 18px;border-radius:12px;font-weight:800;cursor:pointer}button.small{padding:8px 10px;border-radius:9px;border:1px solid var(--line);background:#0c1528;color:var(--text);cursor:pointer}.pill{display:inline-block;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800}.P1{background:rgba(255,92,122,.18);color:var(--red);border:1px solid rgba(255,92,122,.5)}.P2{background:rgba(255,184,107,.16);color:var(--orange);border:1px solid rgba(255,184,107,.5)}.P3{background:rgba(248,225,108,.14);color:var(--yellow);border:1px solid rgba(248,225,108,.45)}.P4{background:rgba(99,230,190,.13);color:var(--green);border:1px solid rgba(99,230,190,.45)}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}th{color:#bcd0f7;font-size:13px}code,pre{background:#08101f;border:1px solid #263755;border-radius:10px;color:#d6e4ff}pre{padding:12px;overflow:auto}.metric{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:14px}.metric b{font-size:24px}.muted{color:var(--muted)}.hide{display:none} .verify-badge { display:inline-block; margin-top:10px; padding:12px 16px; border-radius:8px; background:rgba(88,166,255,0.1); border:1px solid var(--blue); font-size:14px; } .verify-badge.fail { background:rgba(255,92,122,0.1); border-color:var(--red); } .api-box { display:flex; gap:8px; align-items:center; background:var(--panel2); padding:10px 15px; border-radius:12px; border:1px solid var(--line); } .api-box input { width:260px; margin:0; padding:8px; }
</style></head><body>
<header>
    <div><h1>SOC Pilot Agent</h1><div class="sub">1차 분석 및 사용자가 원할 때 수동으로 제3자(Auditor) AI 검증을 수행하는 실무형 SOAR</div></div>
    <div class="api-box">
        <span style="font-size:13px;color:var(--muted);">API 연동키</span>
        <input type="password" id="global_api_key" placeholder="API Key 입력 (비우면 룰베이스)">
        <button class="small" onclick="checkApiKey()">확인</button>
    </div>
</header>
<div class="wrap"><nav><button class="active" onclick="tab('single',this)">단일 알림 처리</button><button onclick="tab('bulk',this)">CSV 대량 처리</button><button onclick="tab('incidents',this);loadIncidents()">사건 큐</button><button onclick="tab('demo',this)">시연 샘플</button></nav><main>
<section id="single" class="page"><div class="card"><h2>단일 알림 생성</h2><div class="grid"><div><label>Alert Type</label><select id="alert_type"><option>login_failed</option><option>ransomware</option><option>malware</option><option>data_exfiltration</option><option>secret_leak</option><option>phishing</option><option>generic</option></select></div><div><label>Host</label><input id="host" value="VPN-GW-01"></div><div><label>User</label><input id="user" value="admin"></div><div><label>Source IP</label><input id="src_ip" value="185.199.110.153"></div><div><label>Destination IP</label><input id="dst_ip" value="10.10.3.15"></div><div><label>Failed Count</label><input id="failed_count" value="67"></div><div><label>Bytes Out</label><input id="bytes_out" value="0"></div><div><label>Process</label><input id="process" value="sshd"></div><div><label>File Path</label><input id="file_path" value=""></div></div><label>Command Line / Raw Message</label><textarea id="command_line">multiple failed login from external IP</textarea><div class="grid2"><div><label>URL</label><input id="url" value=""></div><div><label>Options</label><label><input type="checkbox" id="clicked" style="width:auto"> 링크 클릭함</label><label><input type="checkbox" id="credentials_entered" style="width:auto"> 계정정보 입력함</label></div></div><br><button class="primary" onclick="analyzeSingle()">에이전트 1차 실행</button></div><div id="singleResult"></div></section>
<section id="bulk" class="page hide"><div class="card"><h2>CSV 대량 알림 처리</h2><p class="muted">패턴 자동 병합 후 1차 분석을 진행합니다.</p><textarea id="csvText" style="min-height:260px"></textarea><br><br><button class="primary" onclick="importCsv()">CSV 일괄 사건화</button></div><div id="bulkResult"></div></section>
<section id="incidents" class="page hide"><div class="card"><h2>사건 큐</h2><div id="incidentList">불러오는 중...</div></div><div id="incidentDetail"></div></section>
<section id="demo" class="page hide"><div class="card"><h2>시연 샘플</h2><p>버튼 누르면 CSV 탭에 샘플이 채워짐.</p><button class="primary" onclick="fillSample()">샘플 CSV 채우기</button><pre id="samplePreview"></pre></div></section>
</main></div><script>
const sampleCsv = `alert_type,host,user,src_ip,dst_ip,failed_count,bytes_out,process,command_line,file_path,url,clicked,credentials_entered
login_failed,VPN-GW,admin,1.1.1.1,10.0.0.1,1,0,sshd,"failed login attempt",,,false,false
login_failed,VPN-GW,admin,1.1.1.1,10.0.0.1,1,0,sshd,"failed login attempt",,,false,false
ransomware,PC-01,user1,10.0.0.5,10.0.0.6,0,0,cmd.exe,"vssadmin delete shadows /all /quiet",,,false,false
unknown_anomaly,DB-01,db_svc,192.168.1.10,8.8.8.8,0,500000000,sqlservr.exe,"SELECT * FROM users INTO OUTFILE",,,false,false`;
document.getElementById('csvText').value = sampleCsv; document.getElementById('samplePreview').textContent = sampleCsv;
function tab(id,btn){document.querySelectorAll('.page').forEach(x=>x.classList.add('hide'));document.getElementById(id).classList.remove('hide');document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));btn.classList.add('active')}
function sevClass(s){return (s||'P4').split(' ')[0]} function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]))}
async function post(url,data){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const t=await r.text();let j={};try{j=JSON.parse(t)}catch(e){j={error:t}}if(!r.ok){throw new Error(j.error||('HTTP '+r.status))}return j}
function showErr(where,e){document.getElementById(where).innerHTML=`<div class="card"><h2>오류 발생</h2><p style="color:#ff5c7a">${esc(e.message||e)}</p></div>`}

async function checkApiKey() {
    const k = document.getElementById('global_api_key').value;
    if(!k) { alert("API 키 입력부터 해라 마."); return; }
    const btn = document.querySelector('.api-box button');
    btn.innerText = "확인중.."; btn.disabled = true;
    try {
        const res = await post('/api/check_key', {api_key: k});
        alert("✔️ API 등록 및 통신 성공했다 마! 정상 작동함.");
    } catch(e) {
        alert("❌ API 연동 실패: " + e.message);
    }
    btn.innerText = "확인"; btn.disabled = false;
}

function renderVerification(v, id, context) { 
    if(!v || !v.reason || Object.keys(v).length === 0) {
        return `<div style="margin-top:10px;"><button id="btn_verify_${id}" class="small" style="background:var(--blue);color:white;border:none;padding:10px 15px;font-weight:bold;cursor:pointer;" onclick="verifyIncident('${id}', '${context}')">🤖 제3자 AI 교차 검증 시작</button></div>`;
    }
    const isPass = v.agree; 
    return `<div class="verify-badge ${isPass?'':'fail'}"><b>[제3자 AI 검증 완료]</b> ${isPass?'동의':'불일치'} (신뢰도: ${v.confidence}%)<br><span style="color:var(--muted);display:block;margin-top:4px;">사유: ${esc(v.reason)}</span></div>`; 
}

async function verifyIncident(id, context) {
    const apiKey = document.getElementById('global_api_key').value;
    if(!apiKey) { alert("우측 상단에 API Key를 먼저 넣어라 마."); return; }
    const btn = document.getElementById('btn_verify_' + id);
    if(btn) { btn.innerText = "제3자 검증 분석 중... (시간 소요)"; btn.disabled = true; }
    try {
        await post('/api/verify', {id: id, api_key: apiKey});
        if(context === 'single') {
            const r=await fetch('/api/incident?id='+encodeURIComponent(id));
            const inc=await r.json();
            document.getElementById('singleResult').innerHTML=renderCreated(inc);
        } else {
            showIncident(id);
        }
    } catch(e) {
        alert("검증 에러: " + e.message);
        if(btn) { btn.innerText = "🤖 제3자 AI 교차 검증 시작"; btn.disabled = false; }
    }
}

async function analyzeSingle(){try{const ids=['alert_type','host','user','src_ip','dst_ip','failed_count','bytes_out','process','command_line','file_path','url'];let a={};ids.forEach(id=>a[id]=document.getElementById(id).value);a.clicked=document.getElementById('clicked').checked;a.credentials_entered=document.getElementById('credentials_entered').checked;const res=await post('/api/analyze',{alert:a, api_key:document.getElementById('global_api_key').value});if(!res.result) throw new Error(res.error||'서버 에러');document.getElementById('singleResult').innerHTML=renderCreated(res);document.getElementById('singleResult').scrollIntoView({behavior:'smooth',block:'start'})}catch(e){showErr('singleResult',e)}}
function renderCreated(res){
    const r = res.result || res.alert; // 단일 갱신시 포맷 차이 호환
    const id = res.id;
    return `<div class="card"><h2>생성 완료: ${esc(id)}</h2><div class="grid"><div class="metric"><div class="muted">위험도</div><b>${r.score}/100</b></div><div class="metric"><div class="muted">등급</div><span class="pill ${sevClass(r.severity)}">${esc(r.severity)}</span></div><div class="metric"><div class="muted">플레이북</div><b style="font-size:18px">${esc(r.playbook_name)}</b></div></div>${renderVerification(r.verification, id, 'single')}<h3>요약</h3><p>${esc(r.executive_summary)}</p><h3>근거</h3>${renderEvidence(r.evidence)}<h3>대응 액션</h3>${renderActions(res.actions||r.actions,false)}<p><button class="small" onclick="downloadReport('${id}')">보고서 다운로드</button></p></div>`
}
function renderEvidence(ev){return `<table><tr><th>점수</th><th>근거</th></tr>${ev.map(e=>`<tr><td>${e.score}</td><td>${esc(e.text)}</td></tr>`).join('')}</table>`}
function renderActions(acts,withButtons){return `<table><tr><th>상태</th><th>단계</th><th>담당</th><th>조치</th><th>명령/티켓 내용</th><th></th></tr>${acts.map(a=>`<tr><td>${esc(a.status||'대기')}</td><td>${esc(a.phase)}</td><td>${esc(a.owner)}</td><td>${esc(a.action)}</td><td><code>${esc(a.command)}</code></td><td>${withButtons?`<button class="small" onclick="setAction(${a.id},'완료')">완료</button>`:''}</td></tr>`).join('')}</table>`}
async function importCsv(){try{const res=await post('/api/import_csv',{csv:document.getElementById('csvText').value, api_key:document.getElementById('global_api_key').value});document.getElementById('bulkResult').innerHTML=`<div class="card"><h2>${res.count}개 사건 생성 (병합 완료)</h2><table><tr><th>ID</th><th>등급</th><th>점수</th><th>플레이북</th><th>제목</th></tr>${res.items.map(x=>`<tr><td><button class="small" onclick="showIncident('${x.id}')">${x.id}</button></td><td><span class="pill ${sevClass(x.severity)}">${x.severity}</span></td><td>${x.score}</td><td>${esc(x.playbook)}</td><td>${esc(x.title)}</td></tr>`).join('')}</table></div>`;document.getElementById('bulkResult').scrollIntoView({behavior:'smooth',block:'start'})}catch(e){showErr('bulkResult',e)}}
async function loadIncidents(){const r=await fetch('/api/incidents');const res=await r.json();document.getElementById('incidentList').innerHTML=`<table><tr><th>ID</th><th>생성</th><th>등급</th><th>점수</th><th>상태</th><th>제목</th></tr>${res.items.map(x=>`<tr><td><button class="small" onclick="showIncident('${x.id}')">${x.id}</button></td><td>${x.created_at}</td><td><span class="pill ${sevClass(x.severity)}">${x.severity}</span></td><td>${x.score}</td><td>${x.status}</td><td>${esc(x.title)}</td></tr>`).join('')}</table>`}
async function showIncident(id){const r=await fetch('/api/incident?id='+encodeURIComponent(id));const inc=await r.json();document.getElementById('incidentDetail').innerHTML=`<div class="card"><h2>${esc(inc.id)} 상세</h2>${renderVerification(inc.result.verification, inc.id, 'detail')}<p>${esc(inc.result.executive_summary)}</p><h3>MITRE</h3><ul>${inc.result.mitre.map(x=>`<li>${esc(x)}</li>`).join('')}</ul><h3>근거</h3>${renderEvidence(inc.result.evidence)}<h3>액션</h3>${renderActions(inc.actions,true)}<br><button class="small" onclick="downloadReport('${inc.id}')">보고서 다운로드</button><h3>Raw Alert</h3><pre>${esc(JSON.stringify(inc.alert,null,2))}</pre></div>`}
async function setAction(id,status){await post('/api/action',{id,status});loadIncidents()} function downloadReport(id){window.location='/api/report?id='+encodeURIComponent(id)} function fillSample(){document.getElementById('csvText').value=sampleCsv;document.querySelectorAll('nav button')[1].click()}
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return
    def send_body(self, status, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str): body = body.encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def read_json(self):
        n = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(n).decode("utf-8"); return json.loads(raw or "{}")
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/": self.send_body(200, HTML, "text/html; charset=utf-8")
        elif p.path == "/api/incidents": self.send_body(200, json.dumps({"items": list_incidents()}, ensure_ascii=False))
        elif p.path == "/api/incident":
            inc = get_incident(parse_qs(p.query).get("id", [""])[0]); self.send_body(200 if inc else 404, json.dumps(inc or {"error":"not found"}, ensure_ascii=False))
        elif p.path == "/api/report":
            iid = parse_qs(p.query).get("id", [""])[0]; body = report_text(iid).encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "text/markdown; charset=utf-8"); self.send_header("Content-Disposition", f"attachment; filename={iid}_report.md"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else: self.send_body(404, json.dumps({"error":"not found"}))
    def do_POST(self):
        p = urlparse(self.path)
        try:
            data = self.read_json()
            if p.path == "/api/check_key":
                api_key = data.get("api_key", "")
                if not api_key: raise Exception("API Key가 비어있습니다.")
                client = get_ai_client(api_key)
                if not client: raise Exception("클라이언트 생성 불가")
                try:
                    # 키가 정상 작동하는지 가볍게 핑 날림
                    client.chat.completions.create(
                        model="gpt-4o-mini" if api_key.startswith("sk-") else "claude-sonnet-4-6",
                        messages=[{"role": "user", "content": "ping"}],
                        max_tokens=1
                    )
                    self.send_body(200, json.dumps({"ok": True}, ensure_ascii=False))
                except Exception as e:
                    raise Exception(f"인증 에러: {e}")
            elif p.path == "/api/analyze":
                api_key = data.get("api_key", "")
                result = build_result(data.get("alert"), api_key)
                iid = save_incident(data.get("alert"), result)
                inc = get_incident(iid)
                self.send_body(200, json.dumps({"id": iid, "result": result, "actions": inc["actions"]}, ensure_ascii=False))
            elif p.path == "/api/import_csv":
                api_key = data.get("api_key", "")
                items = import_csv_text(data.get("csv", ""), api_key)
                self.send_body(200, json.dumps({"count": len(items), "items": items}, ensure_ascii=False))
            elif p.path == "/api/verify":
                iid = data.get("id")
                api_key = data.get("api_key", "")
                if not api_key: raise Exception("API Key가 누락되었습니다.")
                con = get_db()
                inc = get_incident(iid)
                if not inc: raise Exception("해당 사건을 찾을 수 없습니다.")
                r = inc["result"]
                ver = verify_ai(inc["alert"], r["playbook"], r["score"], r["evidence"], api_key)
                r["verification"] = ver
                con.execute("update incidents set result_json=? where id=?", (json.dumps(r, ensure_ascii=False), iid))
                con.commit()
                con.close()
                self.send_body(200, json.dumps({"ok": True}, ensure_ascii=False))
            elif p.path == "/api/action":
                set_action_status(data.get("id"), data.get("status", "완료")); self.send_body(200, json.dumps({"ok": True}, ensure_ascii=False))
            else: self.send_body(404, json.dumps({"error":"not found"}))
        except Exception as e:
            self.send_body(500, json.dumps({"error": str(e)}, ensure_ascii=False))

def main():
    init_db(); url = f"http://{HOST}:{PORT}"; print(f"SOC Pilot Agent running: {url}")
    if "--no-browser" not in sys.argv:
        try: webbrowser.open(url)
        except Exception: pass
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()