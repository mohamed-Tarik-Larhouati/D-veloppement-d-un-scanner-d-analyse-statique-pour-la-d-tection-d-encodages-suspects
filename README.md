# Malware Encoding Detector — Static Analysis Scanner

A Python-based static analysis scanner that detects suspicious encodings (Base64, hex, high-entropy strings) and dangerous keywords in files. Optionally integrates with the Claude AI API for deeper analysis.

---

## Features

- **Keyword detection** — flags dangerous functions (`eval`, `os.system`, `subprocess`, `socket`, `pickle`, `marshal`, etc.) with weighted scores
- **Base64 detection** — finds and decodes Base64 blobs, computes Shannon entropy, checks XOR suspicion on decoded bytes
- **Hex detection** — detects `\xNN` escape sequences and raw hex strings, attempts UTF-8 decoding
- **Entropy analysis** — classifies strings as LOW / MEDIUM / HIGH entropy
- **XOR suspicion** — brute-forces all 255 single-byte XOR keys on decoded bytes to detect XOR-obfuscated payloads
- **AI analysis (optional)** — sends extracted features to Claude (claude-sonnet-4-6) for a structured verdict
- **HTML report** — generates a styled `report.html` with a full detection table
- **JSON report** — exports `report.json` for programmatic consumption

---

## Risk Levels

| Score | Level    |
|-------|----------|
| 0     | PROPRE   |
| 1–29  | FAIBLE   |
| 30–59 | MOYEN    |
| 60–79 | ÉLEVÉ    |
| 80–100| CRITIQUE |

---

## Requirements

```
Python 3.8+
anthropic        # only required for --ia flag
```

Install the optional AI dependency:

```bash
pip install anthropic
```

Set your API key (required for `--ia`):

```bash
# Windows
set ANTHROPIC_API_KEY=sk-ant-...

# Linux / macOS
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
# Basic scan
python scanner.py <file>

# Generate HTML report
python scanner.py <file> --html

# Generate JSON report
python scanner.py <file> --json

# Enable AI analysis (requires ANTHROPIC_API_KEY)
python scanner.py <file> --ia

# Full report with AI
python scanner.py <file> --html --json --ia
```

---

## Test Files

The following test files are included to validate each detection scenario:

| File | Expected Level | Score | Purpose |
|------|---------------|-------|---------|
| `normal.txt` | PROPRE | 0 | Clean Lorem Ipsum — no detections |
| `test_propre.py` | PROPRE | 0 | Clean Python script — no keywords, no encodings |
| `test_moyen.txt` | FAIBLE/MOYEN | low | Base64 config, one network library |
| `hidden_hex.txt` | FAIBLE | low | Single `\xNN` hex sequence in prose text |
| `hidden_b64.txt` | CRITIQUE | high | Base64 payloads + dangerous keywords + PowerShell |
| `tester.txt` | ÉLEVÉ/CRITIQUE | high | Mixed keywords, Base64 commands, hex sequences |
| `test_shellcode.txt` | CRITIQUE | 85 | Decimal byte arrays + MZ/ELF hex headers |
| `test_high_entropy.txt` | CRITIQUE | 100 | High-entropy Base64 blobs (simulated AES/RC4 payloads) |
| `test_critique.py` | CRITIQUE | 100 | Multiple dangerous keywords + Base64 + hex + XOR |

### Run all test files

```bash
python scanner.py normal.txt
python scanner.py test_propre.py
python scanner.py test_moyen.txt
python scanner.py hidden_hex.txt
python scanner.py hidden_b64.txt --html --json
python scanner.py tester.txt --html --json
python scanner.py test_shellcode.txt --html
python scanner.py test_high_entropy.txt --html
python scanner.py test_critique.py --html --json
```

---

## Output Files

| File | Description |
|------|-------------|
| `report.html` | Visual HTML report (overwritten on each run) |
| `report.json` | Structured JSON report (overwritten on each run) |

---

## Project Structure

```
scanner.py               # Main scanner
report.json              # Last JSON report
rapport_analyse.html     # Sample HTML report
normal.txt               # Clean test file
hidden_b64.txt           # Base64 + keyword test file
hidden_hex.txt           # Hex encoding test file
tester.txt               # Mixed detections test file
test_moyen.txt           # Low/medium risk test file
test_propre.py           # PROPRE level test (score 0)
test_critique.py         # CRITIQUE level test (score 100)
test_shellcode.txt       # Decimal byte array + hex test
test_high_entropy.txt    # High-entropy payload test
```

---

## How Scoring Works

Each detection adds points to the risk score (capped at 100):

- Suspicious keyword match: **+10 to +50** (depending on severity)
- Base64 blob found: **+20**
- Base64 entropy > 4.0: **+15**
- XOR suspicion on decoded bytes: **+30**
- Hex sequence found: **+15**
- Keyword found inside decoded Base64: **+keyword score**

---

## AI Analysis Detail

When `--ia` is passed, the scanner:
1. Extracts a structured feature dataset (keywords, hex, decimal arrays, high-entropy strings, Base64 blobs)
2. Sends it to Claude via the Anthropic API
3. Receives a JSON verdict with risk level, score, confidence, per-finding details, and a recommended action (`BLOCK / INVESTIGATE / MONITOR / ALLOW`)
4. Appends the AI result to both the console output and the HTML/JSON reports
