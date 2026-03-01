# 🛡️ SpyShield — Spyware & Threat Detector

A lightweight, real-time spyware and threat detection tool built with Python and Tkinter. SpyShield scans running processes and network connections against a built-in database of known malicious signatures and suspicious heuristics, then presents the results in a clean GUI dashboard.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- **Process Scanner** — checks all running processes against known malicious names (RATs, keyloggers, stealers, etc.)
- **Network Monitor** — flags connections on suspicious ports and unknown processes using standard web ports
- **Heuristic Analysis** — detects suspicious patterns beyond exact name matches
- **Risk Score** — calculates a 0–100 risk score based on threat severity
- **Scan History** — keeps a bounded stack of the last 20 scan summaries
- **CSV Export** — save the full threat log to a report file
- **Custom Data Structures** — uses a hand-rolled linked list, hash table, and stack (no external data-structure libraries)

---

## 📋 Requirements

- Python 3.8 or higher
- [psutil](https://pypi.org/project/psutil/)
- Tkinter (bundled with most Python installations)

---

## 🚀 Installation & Usage

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/spyshield.git
cd spyshield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python spyware_detector.py
```

> **Windows note:** For full network connection data, run the terminal / Command Prompt as **Administrator**.

> **Linux / macOS note:** You may need to prefix the run command with `sudo` to read all network connections.

---

## 🖥️ Screenshots

> _Add screenshots here once the app is running._

---

## 🗂️ Project Structure

```
spyshield/
├── spyware_detector.py   # Main application (GUI + detection engine)
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── LICENSE               # MIT License
└── .gitignore            # Files excluded from version control
```

---

## ⚙️ How It Works

| Component | Description |
|---|---|
| `ThreatLinkedList` | Singly-linked list storing detected threat dictionaries |
| `HashTable` | DJB2-hashed table for O(1) signature lookups |
| `ScanHistoryStack` | Bounded stack keeping the last 20 scan summaries |
| `SpywareDetector` | Core engine: process scan, network scan, heuristics, risk scoring |
| `SpyShieldApp` | Tkinter GUI wrapping the detector with live tables and dashboard cards |

---

## 🔒 Disclaimer

SpyShield is an **educational and personal-use tool**. It uses static signature matching and basic heuristics — it is **not** a replacement for professional antivirus or endpoint-detection software. False positives and false negatives are both possible.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
