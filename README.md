# 🛡️ Malware Scanner

This is a Python-based malware scanner designed to help detect malicious files using open-source antivirus tools. It leverages **ClamAV**, **YARA rules**, and supports multiprocessing for faster scanning. The tool also includes a **PyQt5-based GUI** for ease of use.

---

## 🚀 Features

- 🔍 Scan files and directories using **ClamAV**
- 🧠 Match files against **custom YARA rules**
- ⚡ Uses **multiprocessing** to speed up large scans
- 📂 Caches previously scanned files to skip duplicates
- 🗃️ **Quarantine system** to isolate infected files
- 🖥️ Easy-to-use **desktop GUI** (built with PyQt5)
- 📄 Detailed logging for scan results

---

## 🧰 Requirements

- Python 3.10+
- ClamAV installed and running
- YARA installed
- PyQt5
- Other Python dependencies (see `requirements.txt`)

---

## 📦 Installation

1. Clone this repo:
   ```bash
   git clone https://github.com/youness2k4/mallware-scanner-.git
   cd mallware-scanner-
