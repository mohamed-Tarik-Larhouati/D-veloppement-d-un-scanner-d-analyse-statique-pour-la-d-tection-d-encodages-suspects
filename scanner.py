import re
import base64
import sys
import json
import math
import html
import argparse
from collections import Counter


# =========================
# SUSPICIOUS KEYWORDS
# =========================
suspicious_keywords = {
    "os.system": 50, "exec": 50, "eval": 50, "subprocess": 40,
    "popen": 40, "pty.spawn": 50, "shell": 30, "powershell": 50,
    "cmd.exe": 40, "/bin/sh": 45, "/bin/bash": 45,
    "socket": 40, "requests": 10, "urllib": 15, "wget": 30, "curl": 30,
    "base64": 5,
    "marshal": 45, "pickle": 45, "binascii": 20,
    "__import__": 40,
    "chmod": 30, "tempfile": 15, "shutil": 15, "os.remove": 25
}


# =========================
# ENTROPY
# =========================
def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def classify_entropy(e):
    if e < 3.0:
        return "LOW"
    elif e < 4.0:
        return "MEDIUM"
    return "HIGH"


# =========================
# BASE64 CHECK
# =========================
def is_valid_base64(s):
    try:
        base64.b64decode(s, validate=True)
        return True
    except:
        return False


# =========================
# XOR CHECK ON DECODED BYTES
# =========================
def xor_suspicion_bytes(raw_bytes: bytes) -> bool:
    if not raw_bytes or len(raw_bytes) < 4:
        return False
    try:
        for key in range(1, 256):
            decoded = bytes([b ^ key for b in raw_bytes])
            readable = sum(32 <= c <= 126 for c in decoded) / len(decoded)
            if readable > 0.85:
                return True
    except:
        pass
    return False


# =========================
# IA ANALYSIS FEATURE
# =========================
def extract_features_for_ia(file_path: str) -> dict:
    """
    Extracts a structured dataset from the file for AI analysis.
    Returns a dict with:
      - suspicious_functions found (name, line)
      - hex sequences (line, value, decoded attempt)
      - decimal sequences (line, value)
      - high-entropy strings
      - base64 blobs (line, decoded preview)
    """
    features = {
        "suspicious_functions": [],
        "hex_sequences": [],
        "decimal_sequences": [],
        "high_entropy_strings": [],
        "base64_blobs": [],
        "raw_line_count": 0,
    }

    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){3,}(?:==|=)?'
    hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}){8,}'
    decimal_pattern = r'\b(?:\d{1,3}(?:,\s*\d{1,3}){5,})\b'  # comma-separated decimals (shellcode style)

    seen_keywords = set()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    features["raw_line_count"] = len(lines)

    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        stripped = line.strip()

        # --- Suspicious functions / keywords ---
        for kw in suspicious_keywords:
            if kw in line_lower and kw not in seen_keywords:
                seen_keywords.add(kw)
                features["suspicious_functions"].append({
                    "keyword": kw,
                    "line": line_num,
                    "context": stripped[:120]
                })

        # --- Hex sequences ---
        for m in re.finditer(hex_pattern, line):
            hex_raw = m.group()
            hex_clean = hex_raw.replace("\\x", "")
            decoded_attempt = ""
            try:
                decoded_attempt = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
            except:
                pass
            features["hex_sequences"].append({
                "line": line_num,
                "hex": hex_raw[:80],
                "decoded_preview": decoded_attempt[:60]
            })

        # --- Decimal sequences (shellcode-style arrays) ---
        for m in re.finditer(decimal_pattern, line):
            features["decimal_sequences"].append({
                "line": line_num,
                "value": m.group()[:100]
            })

        # --- High-entropy strings (tokens > 12 chars) ---
        for token in re.findall(r'[A-Za-z0-9+/=_\-]{12,}', line):
            ent = calculate_entropy(token)
            if ent > 4.5:
                features["high_entropy_strings"].append({
                    "line": line_num,
                    "token": token[:80],
                    "entropy": round(ent, 2)
                })

        # --- Base64 blobs ---
        for m in re.finditer(b64_pattern, line):
            encoded = m.group()
            if len(encoded) < 12 or not is_valid_base64(encoded):
                continue
            decoded_str = ""
            try:
                decoded_str = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            except:
                pass
            features["base64_blobs"].append({
                "line": line_num,
                "encoded_preview": encoded[:60],
                "decoded_preview": decoded_str[:60],
                "entropy": round(calculate_entropy(encoded), 2)
            })

    return features


def analyse_with_ia(file_path: str) -> dict:
    """
    Sends the extracted features to Claude API for AI-powered analysis.
    Returns a structured dict with the AI verdict.
    """
    try:
        import anthropic
    except ImportError:
        print("[!] anthropic package not found. Install it with: pip install anthropic")
        sys.exit(1)

    print("\n[*] Extracting features for AI analysis...")
    features = extract_features_for_ia(file_path)

    # Build a compact dataset string for the prompt
    dataset_summary = json.dumps(features, indent=2, ensure_ascii=False)
    # Truncate if too large to stay within context limits
    if len(dataset_summary) > 12000:
        dataset_summary = dataset_summary[:12000] + "\n... [truncated]"

    system_prompt = """You are a malware analysis expert. You receive a structured dataset extracted from a source file.
Your job is to analyze the dataset and return a JSON object ONLY — no preamble, no markdown, no backticks.

The JSON must have exactly these fields:
{
  "ai_risk_level": "CRITIQUE|ELEVÉ|MOYEN|FAIBLE|PROPRE",
  "ai_risk_score": <integer 0-100>,
  "confidence": "HIGH|MEDIUM|LOW",
  "findings": [
    {
      "category": "hex_obfuscation|decimal_shellcode|suspicious_function|base64_payload|high_entropy|other",
      "severity": "critical|high|medium|low",
      "description": "<concise explanation in English>",
      "line": <line number or null>
    }
  ],
  "summary": "<2-3 sentence overall verdict>",
  "recommended_action": "BLOCK|INVESTIGATE|MONITOR|ALLOW"
}

Rules:
- Base your analysis on the actual data provided, not assumptions.
- Flag decimal arrays that look like shellcode (byte values 0-255 in a list).
- Flag hex sequences that decode to executable-looking strings.
- Flag base64 blobs whose decoded content contains known malicious patterns.
- Flag high-entropy strings that could be encrypted payloads.
- Be conservative: only mark CRITIQUE if there is strong evidence."""

    user_prompt = f"""Analyze this file: {file_path}

Extracted feature dataset:
{dataset_summary}"""

    print("[*] Sending to Claude AI for analysis...")
    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    raw_text = response.content[0].text.strip()

    # Strip markdown fences if present
    raw_text = re.sub(r'^```json\s*', '', raw_text)
    raw_text = re.sub(r'^```\s*', '', raw_text)
    raw_text = re.sub(r'\s*```$', '', raw_text)

    try:
        ai_result = json.loads(raw_text)
    except json.JSONDecodeError:
        print(f"[!] AI returned non-JSON response:\n{raw_text}")
        ai_result = {
            "ai_risk_level": "UNKNOWN",
            "ai_risk_score": -1,
            "confidence": "LOW",
            "findings": [],
            "summary": raw_text[:300],
            "recommended_action": "INVESTIGATE"
        }

    return ai_result, features


def print_ia_report(ai_result: dict, file_path: str):
    """Print a formatted AI analysis report to the console."""
    level_icons = {
        "CRITIQUE": "🔴", "ELEVÉ": "🟠", "MOYEN": "🟡",
        "FAIBLE": "🟢", "PROPRE": "✅", "UNKNOWN": "❓"
    }
    action_icons = {
        "BLOCK": "🚫", "INVESTIGATE": "🔍", "MONITOR": "👁️", "ALLOW": "✅"
    }

    level = ai_result.get("ai_risk_level", "UNKNOWN")
    score = ai_result.get("ai_risk_score", "?")
    confidence = ai_result.get("confidence", "?")
    summary = ai_result.get("summary", "No summary.")
    action = ai_result.get("recommended_action", "?")
    findings = ai_result.get("findings", [])

    print("\n" + "=" * 60)
    print("AI ANALYSIS REPORT")
    print("=" * 60)
    print(f"File     : {file_path}")
    print(f"Risk     : {level_icons.get(level, '?')} {level} — {score}/100  (confidence: {confidence})")
    print(f"Action   : {action_icons.get(action, '')} {action}")
    print(f"Summary  : {summary}")

    if findings:
        print("\nFindings:")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "?").upper()
            cat = f.get("category", "?")
            desc = f.get("description", "")
            line = f.get("line")
            line_str = f" (line {line})" if line else ""
            print(f"  [{i}] [{sev}] {cat}{line_str}: {desc}")
    else:
        print("\nNo specific findings.")
    print("=" * 60)


def generate_html_report_with_ia(report: dict, ai_result: dict = None):
    """Generates HTML report, optionally including AI analysis section."""
    level_colors = {
        "CRITIQUE": "#c0392b", "ELEVÉ": "#e67e22",
        "MOYEN": "#d4a017",    "FAIBLE": "#27ae60",
        "PROPRE": "#2980b9",   "UNKNOWN": "#7f8c8d"
    }
    color = level_colors.get(report["risk_level"], "#333")

    rows = ""
    for d in report["detections"]:
        content = d.get("decoded", d.get("encoded", ""))
        rows += f"""
        <tr>
            <td>{d.get('line', '-')}</td>
            <td><span class="badge {d['type']}">{d['type'].upper()}</span></td>
            <td class="code">{html.escape(str(content)[:120])}</td>
            <td>{d.get('entropy', '-')}</td>
            <td>{'⚠️ XOR' if d.get('xor_suspect') else ''}</td>
        </tr>"""

    # AI section
    ai_section = ""
    if ai_result:
        ai_level = ai_result.get("ai_risk_level", "UNKNOWN")
        ai_score = ai_result.get("ai_risk_score", "?")
        ai_conf  = ai_result.get("confidence", "?")
        ai_summ  = html.escape(ai_result.get("summary", ""))
        ai_action = ai_result.get("recommended_action", "?")
        ai_color  = level_colors.get(ai_level, "#7f8c8d")

        findings_rows = ""
        for f in ai_result.get("findings", []):
            sev  = html.escape(f.get("severity", "").upper())
            cat  = html.escape(f.get("category", ""))
            desc = html.escape(f.get("description", ""))
            line = f.get("line", "-")
            findings_rows += f"<tr><td>{line}</td><td>{sev}</td><td>{cat}</td><td>{desc}</td></tr>"

        ai_section = f"""
    <div class="card" style="margin-top:24px;">
      <h2 style="font-size:16px;">🤖 AI Analysis (Claude)</h2>
      <div style="display:flex; gap:16px; align-items:center; margin:12px 0;">
        <div class="score-box" style="background:{ai_color}; font-size:20px; padding:8px 18px;">
          {ai_level} — {ai_score}/100
        </div>
        <div>
          <div><strong>Confidence:</strong> {html.escape(ai_conf)}</div>
          <div><strong>Recommended Action:</strong> {html.escape(ai_action)}</div>
        </div>
      </div>
      <p><strong>Summary:</strong> {ai_summ}</p>
      <table>
        <thead><tr><th>Line</th><th>Severity</th><th>Category</th><th>Description</th></tr></thead>
        <tbody>
          {findings_rows if findings_rows else '<tr><td colspan="4" class="empty">No AI findings</td></tr>'}
        </tbody>
      </table>
    </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Malware Report — {html.escape(report['file'])}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 24px; }}
    h1 {{ font-size: 20px; margin-bottom: 4px; }}
    h2 {{ font-size: 16px; margin-bottom: 8px; }}
    .meta {{ color: #555; font-size: 13px; margin-bottom: 20px; }}
    .score-box {{ display: inline-block; padding: 12px 24px; border-radius: 8px;
                  background: {color}; color: white; font-size: 28px; font-weight: bold;
                  margin-bottom: 20px; }}
    .card {{ background: white; border-radius: 10px; padding: 24px;
             box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #f8f8f8; padding: 10px; text-align: left;
          border-bottom: 2px solid #ddd; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:hover {{ background: #fafafa; }}
    .code {{ font-family: monospace; font-size: 12px; word-break: break-all; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px;
              font-weight: bold; color: white; }}
    .base64 {{ background: #8e44ad; }}
    .hex    {{ background: #2471a3; }}
    .empty  {{ color: #aaa; font-style: italic; text-align: center; padding: 20px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>🔍 Malware Encoding Detector — v3</h1>
    <p class="meta">Fichier analysé : <strong>{html.escape(report['file'])}</strong></p>
    <div class="score-box">{report['risk_level']} — {report['risk_score']}/100</div>
    <table>
      <thead>
        <tr><th>Ligne</th><th>Type</th><th>Contenu décodé</th><th>Entropie</th><th>XOR</th></tr>
      </thead>
      <tbody>
        {rows if rows else '<tr><td colspan="5" class="empty">Aucune détection</td></tr>'}
      </tbody>
    </table>
  </div>
  {ai_section}
</body>
</html>"""

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("[+] HTML report generated → report.html")


# =========================
# HTML REPORT (original, kept for compatibility)
# =========================
def generate_html_report(report):
    generate_html_report_with_ia(report, ai_result=None)


# =========================
# MAIN ANALYSIS
# =========================
def analyse(file_path):
    report = {
        "file": file_path,
        "risk_score": 0,
        "risk_level": "",
        "detections": []
    }

    risk = 0
    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){3,}(?:==|=)?'
    hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}){8,}'

    print("=" * 60)
    print("ANALYSIS:", file_path)
    print("=" * 60)

    seen_keywords = set()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line_lower = line.lower()

            # --- KEYWORDS ---
            for k, score in suspicious_keywords.items():
                if k in line_lower and k not in seen_keywords:
                    risk += score
                    seen_keywords.add(k)
                    print(f"  [KW] Line {line_num}: '{k}' (+{score})")

            # --- BASE64 ---
            for m in re.finditer(b64_pattern, line):
                encoded = m.group()
                if len(encoded) < 12:
                    continue
                if not is_valid_base64(encoded):
                    continue

                entropy = calculate_entropy(encoded)
                risk += 20
                if entropy > 4.0:
                    risk += 15

                decoded_str = ""
                decoded_bytes = b""
                try:
                    decoded_bytes = base64.b64decode(encoded)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                except:
                    pass

                xor_flag = xor_suspicion_bytes(decoded_bytes)
                if xor_flag:
                    risk += 30
                    print(f"  [XOR] Line {line_num}: XOR suspicion on decoded bytes (+30)")

                entry = {
                    "type": "base64",
                    "line": line_num,
                    "encoded": encoded,
                    "decoded": decoded_str,
                    "entropy": round(entropy, 2),
                    "xor_suspect": xor_flag
                }
                report["detections"].append(entry)
                print(f"  [B64] Line {line_num}: entropy={round(entropy,2)} (+20{'+15' if entropy>4 else ''})")

                for k, score in suspicious_keywords.items():
                    if k in decoded_str.lower() and k not in seen_keywords:
                        risk += score
                        seen_keywords.add(k)
                        print(f"  [KW-decoded] '{k}' in decoded content (+{score})")

            # --- HEX ---
            for m in re.finditer(hex_pattern, line):
                hex_raw = m.group()
                hex_clean = hex_raw.replace("\\x", "")
                entropy = calculate_entropy(hex_raw)
                risk += 15

                decoded_str = ""
                try:
                    decoded_str = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
                except:
                    pass

                report["detections"].append({
                    "type": "hex",
                    "line": line_num,
                    "encoded": hex_raw,
                    "decoded": decoded_str,
                    "entropy": round(entropy, 2),
                    "xor_suspect": False
                })
                print(f"  [HEX] Line {line_num}: entropy={round(entropy,2)} (+15)")

    # --- FINAL SCORE ---
    risk = max(0, min(risk, 100))

    if risk >= 80:
        level = "CRITIQUE"
    elif risk >= 60:
        level = "ELEVÉ"
    elif risk >= 30:
        level = "MOYEN"
    elif risk > 0:
        level = "FAIBLE"
    else:
        level = "PROPRE"

    report["risk_score"] = risk
    report["risk_level"] = level

    print(f"\nSCORE: {risk}/100")
    print(f"LEVEL: {level}")
    return report


# =========================
# CLI
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Encoding Detector v3")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("--html", action="store_true", help="Generate report.html")
    parser.add_argument("--json", action="store_true", help="Generate report.json")
    parser.add_argument("--ia",   action="store_true",
                        help="Enable AI analysis via Claude API (requires ANTHROPIC_API_KEY)")
    args = parser.parse_args()

    # Standard analysis
    report = analyse(args.file)

    ai_result = None

    # AI analysis
    if args.ia:
        ai_result, features = analyse_with_ia(args.file)
        print_ia_report(ai_result, args.file)
        report["ai_analysis"] = ai_result

    if args.json:
        with open("report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print("[+] JSON generated → report.json")

    if args.html:
        generate_html_report_with_ia(report, ai_result)