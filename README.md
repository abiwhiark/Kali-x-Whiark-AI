# ⚡ Kali x Whiark AI — Autonomous Cybersecurity Operator

> **Whiark × Kali AI** is a professional-grade autonomous cybersecurity assistant and bug hunter.  
> Inspired by HexStrike AI — it uses real Kali Linux tools, opens terminals & browsers on your behalf,  
> runs OWASP ZAP scans, cracks passwords, and generates full penetration testing reports.  
> Powered by **Google Gemini API** with autonomous function calling.

---

## 🚀 Quick Install on Kali Linux (Copy & Paste)

```bash
# 1. Clone the repo
git clone https://github.com/abiwhiark/Kali-x-Whiark-AI.git
cd Kali-x-Whiark-AI

# 2. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# 3. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Upgrade pip
pip install --upgrade pip

# 5. Install all Python dependencies
pip install -r backend/requirements.txt

# 6. Set up your .env file
cp .env.example .env
nano .env
```

Inside `nano`, edit your `.env` to look like this:
```ini
GEMINI_API_KEY=AIza...your_key_here...
GEMINI_MODEL=gemini-2.5-flash
MAX_AGENT_ITERATIONS=10
MAX_TOOL_CALLS=15
TOOL_EXECUTION_TIMEOUT=120
ALLOWED_TARGETS=*
```
Save: `Ctrl+O` → `Enter` → `Ctrl+X`

```bash
# 7. Run Kali AI
python3 cli.py
```

---

## ⚠️ Common Errors & Fixes

### Error: `ImportError: cannot import name 'genai' from 'google'`
```bash
# Fix: Install requirements inside the virtual environment
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
```

### Error: `ModuleNotFoundError: No module named 'dotenv'`
```bash
pip install python-dotenv
```

### Error: `ModuleNotFoundError: No module named 'rich'`
```bash
pip install rich
```

### Error: `python3 cli.py` not working after install
```bash
# Make sure venv is ACTIVE (you must see (venv) in prompt)
source venv/bin/activate
python3 cli.py
```

### Error: `.env` file not found
```bash
cp .env.example .env
nano .env   # add your GEMINI_API_KEY
```

---

## 🔑 Getting a Free Gemini API Key

1. Go to → **https://aistudio.google.com/app/apikey**
2. Click **"Create API Key"**
3. Copy the key (starts with `AIza...`)
4. Paste it in your `.env` file as `GEMINI_API_KEY=AIza...`

---

## 🛠️ Install Kali Security Tools (for real scanning)

```bash
sudo apt install -y \
  nmap nikto gobuster dirb whatweb \
  hydra john sqlmap wpscan masscan \
  subfinder amass zaproxy \
  xterm firefox-esr
```

> Without these, Kali AI still works but uses mock/simulated results.  
> With them installed, **real live scanning** happens.

---

## 💻 Usage — CLI Commands

Start the CLI:
```bash
source venv/bin/activate
python3 cli.py
```

### 🎯 Set a Target & Scan
```
KaliAI ❯ target testphp.vulnweb.com        # authorize target
KaliAI ❯ scan testphp.vulnweb.com          # full AI assessment
KaliAI ❯ nmap scan on testphp.vulnweb.com  # nmap only
KaliAI ❯ sqlmap on http://testphp.vulnweb.com/artists.php?artist=1
KaliAI ❯ find subdomains of vulnweb.com
KaliAI ❯ check ssl on testphp.vulnweb.com
KaliAI ❯ wordpress scan on target.com
```

### 🖥️ Terminal Launcher (opens real Kali terminals)
```
KaliAI ❯ open terminal nmap -sV testphp.vulnweb.com
KaliAI ❯ open tool nikto on testphp.vulnweb.com
KaliAI ❯ open tool gobuster on http://testphp.vulnweb.com
KaliAI ❯ open metasploit
KaliAI ❯ terminals    # list open terminal sessions
```

### 🌐 Browser Launcher (opens real Firefox/Chromium)
```
KaliAI ❯ open browser https://testphp.vulnweb.com
KaliAI ❯ browse zap https://testphp.vulnweb.com    # through ZAP proxy
KaliAI ❯ open zap                                  # open ZAP GUI
```

### 🕷️ OWASP ZAP Auto-Scanner
```
KaliAI ❯ target testphp.vulnweb.com
KaliAI ❯ zap scan http://testphp.vulnweb.com
# → Starts ZAP daemon
# → Opens Firefox (you watch it crawl live!)
# → Spiders all pages
# → Runs active attack scan
# → Generates full report with CVSS/CWE
```

### 🔑 Password Cracking
```
KaliAI ❯ brute force ssh on 192.168.1.1
KaliAI ❯ crack hashes /path/to/hashes.txt
```

### 📂 File Access
```
KaliAI ❯ read file /etc/passwd
KaliAI ❯ ls /home/kali/
```

### 💬 Chat (like ChatGPT)
```
KaliAI ❯ what is SQL injection?
KaliAI ❯ how do I exploit CVE-2021-44228?
KaliAI ❯ explain OWASP Top 10
KaliAI ❯ write a python port scanner
```

### ⚙️ Other Commands
```
KaliAI ❯ tools           # list AI-registered tools
KaliAI ❯ kali tools      # list all 28 Kali tools + install status
KaliAI ❯ help            # full command reference
KaliAI ❯ target *        # HexStrike Mode: allow ALL targets
KaliAI ❯ yes             # confirm authorization for current target
KaliAI ❯ clear           # clear screen
KaliAI ❯ quit            # exit
```

---

## 🌐 Web Dashboard (Optional)

For the full browser-based UI:

**Terminal 1 — Backend:**
```bash
source venv/bin/activate
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Open: **http://localhost:5173**

---

## 🗂️ Project Structure

```
Kali-x-Whiark-AI/
├── cli.py                              # 🖥️  Main terminal CLI
├── .env.example                        # 📋 Copy to .env and add API key
├── backend/
│   ├── requirements.txt                # 📦 Python dependencies
│   ├── main.py                         # FastAPI app
│   ├── services/
│   │   ├── agent/orchestrator.py       # 🧠 AI decision loop
│   │   ├── kali_tool_runner.py         # ⚔️  28 Kali tools runner
│   │   ├── terminal_launcher.py        # 🖥️  Open real terminals
│   │   ├── browser_launcher.py         # 🌐 Open real browsers
│   │   ├── zap_scanner.py              # 🕷️  OWASP ZAP automation
│   │   ├── password_cracker.py         # 🔑 Hydra / John / Hashcat
│   │   ├── file_access.py              # 📂 Secure file reader
│   │   ├── security/
│   │   │   ├── validator.py            # 🛡️  Security validator
│   │   │   └── consent_gate.py         # ✅ Authorization consent gate
│   │   ├── tool_registry/registry.py   # 🗄️  Tool registry
│   │   ├── gemini/client.py            # 🤖 Gemini AI client
│   │   ├── analysis/
│   │   │   ├── normalizer.py           # Finding normalizer
│   │   │   └── correlator.py           # Finding correlator
│   │   └── reporting/generator.py      # 📊 Report generator
│   └── tests/                          # ✅ 41 pytest tests
└── frontend/                           # React dashboard
```

---

## 🔒 Security & Legal Notice

This tool uses a **Consent Gate** model (same as Metasploit, Burp Suite, Nessus):

- You can scan **any target** after typing `target <host>` or `yes`
- By doing so you confirm you **own the system** or have **written authorization**
- **Unauthorized scanning is illegal** — you are solely responsible
- All consent events are logged with timestamps

---

## 🧰 All 28 Supported Kali Tools

| Category | Tools |
|----------|-------|
| Recon / Ports | `nmap`, `masscan` |
| Web Scanning | `nikto`, `nuclei`, `wpscan` |
| Directory Brute | `gobuster`, `dirb` |
| Fingerprinting | `whatweb`, `curl`, `wget` |
| Injections | `sqlmap`, `xssstrike`, `commix` |
| Password Cracking | `hydra`, `john`, `hashcat`, `aircrack-ng` |
| DNS / Subdomains | `subfinder`, `amass`, `fierce`, `dnsrecon` |
| SSL / TLS | `sslyze`, `testssl` |
| Exploitation | `metasploit` |
| SMB | `enum4linux`, `smbclient` |
| Web App | `burpsuite` |

---

## 👨‍💻 Built by

**Whiark × Kali AI Team**  
Inspired by: HexStrike AI, Metasploit, Burp Suite  
Powered by: Google Gemini API, Kali Linux, Python
