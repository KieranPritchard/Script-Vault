# 🛠️ Script Vault

<div align="center">
    <img alt="GitHub Created At" src="https://img.shields.io/github/created-at/KieranPritchard/Script-Vault?style=flat-square">
    <img alt="GitHub License" src="https://img.shields.io/github/license/KieranPritchard/Script-Vault?style=flat-square">
    <img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/t/KieranPritchard/Script-Vault?style=flat-square">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/KieranPritchard/Script-Vault?style=flat-square">
    <img alt="GitHub language count" src="https://img.shields.io/github/languages/count/KieranPritchard/Script-Vault?style=flat-square">
    <div>
        <img alt="Header Image" src="https://github.com/KieranPritchard/Script-Vault/blob/main/resources/Gemini_Generated_Image_f37h11f37h11f37h.png">
    </div>

**A centralized collection of automation scripts and utility tools designed to streamline workflows and sharpen my programming skills.**

**Note:** Any incomplete scripts without a write up are being worked on. 
</div>

---

## 📌 Overview

The **Script Vault** is an evolving repository where I store useful scripts across various programming languages. This project serves two main purposes:
1. **Efficiency:** Automating repetitive tasks to save time and reduce manual errors.
2. **Skill Development:** Refining my scripting abilities and exploring new libraries and frameworks.

---

## 🚀 Features

* **Task Automation:** Custom scripts to handle boring, repetitive workflows.
* **Centralized Knowledge:** A single source of truth for all my utility code.
* **Multi-language Support:** Solutions in Python, Bash, JavaScript, and shell scripts.
* **Containerized Environment:** Ready-to-use Docker and Docker Compose setups pre-configured with required network and security tooling.

---

## 📂 Vault Contents

| Category | Description | Language |
| :--- | :--- | :--- |
| **data_analysis_scripts** | SQL vulnerability analysis and data processing | Python |
| **development_scripts** | Project organizers, build scripts, Go build helpers | Python / Bash |
| **exploitation** | SQL schema extraction and parsing utilities | Python / JavaScript |
| **file_management_scripts** | Automated downloaded files organizer and file management utilities | Python |
| **networking_scripts** | ARP network discovery, Nmap target scannner, firewall & banner detection | Python / Bash |
| **reconnaissance_scripts** | Website metadata scraper, robots/sitemap analyzer, domain lookup, DNS enum | Python / Bash |
| **vulnerability_detection** | Command injection detection, XSS detection, SQL injection, CVE extraction | Python |

---

## 🛠️ Technologies and Tools

* **Languages:** Python, Bash, Shell, JavaScript
* **Python Libraries:** `scapy`, `python-nmap`, `pandas`, `requests`, `beautifulsoup4`, `tldextract`, `python-whois`, `dnspython`, `matplotlib`, `builtwith`
* **System Utilities:** `nmap`, `net-tools`, `tcpdump`, `dnsutils`

---

## ⚙️ Getting Started

### Option 1: Native Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/KieranPritchard/Script-Vault.git
   cd Script-Vault
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

### Option 2: Running with Docker & Docker Compose

Using Docker ensures all system tools (e.g. `nmap`, `net-tools`, `tcpdump`) and Python dependencies are installed in an isolated environment.

1. **Using Docker Compose (Recommended):**
   ```bash
   # Build and start the container in interactive mode
   docker compose run --rm script-vault
   ```

2. **Using Docker CLI:**
   ```bash
   # Build the image
   docker build -t script-vault .

   # Run an interactive container with network capabilities for scanning scripts
   docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW -v "$(pwd):/app" script-vault
   ```
