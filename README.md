# 🕵️ DomainRecon — Advanced Intelligence Gathering Tool

<div align="center">

![DomainRecon Banner](https://img.shields.io/badge/DomainRecon-Advanced%20Intel-00ffaa?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A professional, full-stack domain reconnaissance platform with an immersive cyberpunk UI and a live hacker-terminal scanning animation.**

[🔗 Live Demo](https://domain-info-swart.vercel.app/) · [🐛 Report Bug](https://github.com/yug1204/domain-info/issues) · [💡 Request Feature](https://github.com/yug1204/domain-info/issues)

</div>

---

## ✨ Features

| Module | What It Does |
|--------|-------------|
| 🔍 **WHOIS Lookup** | Extracts registrar, registrant, creation date, expiry info |
| 🌍 **DNS Analysis** | Resolves A, AAAA, MX, NS, and TXT records in parallel |
| 🔌 **Port Scanner** | Probes common ports (21, 22, 25, 80, 443, 3306, etc.) |
| 🔒 **SSL Certificate** | Reads issuer, subject, validity dates and TLS version |
| 📍 **Geolocation** | IP-based triangulation — country, region, city, ISP |
| 🤖 **Robots.txt** | Extracts and parses hidden crawl directives |
| 📄 **HTTP Headers** | Full web server response header fingerprinting |

---

## 🎬 How It Looks

When you trigger a scan, a **live hacking terminal** appears and streams log lines in real-time:

```
> Initializing deep scan on target: example.com...
> Bypassing edge cache layers...
[OK] Resolving DNS topology [A, AAAA, MX, NS, TXT]...
> Attempting WHOIS registry extraction...
[!] Probing network perimeter for open sockets...
[OK] Analyzing SSL/TLS cryptographic signatures...
> Triangulating server geolocation coordinates...
[!] Extracting hidden robots.txt directives...
[OK] Compiling reconnaissance packet...
```

---

## 🛠️ Tech Stack

**Backend**
- [FastAPI](https://fastapi.tiangolo.com/) — High-performance async REST API framework
- [Uvicorn](https://www.uvicorn.org/) — ASGI web server
- `python-whois` — WHOIS registry queries
- `dnspython` — DNS resolution
- `requests` — HTTP header & robots.txt fetching
- `ssl` + `socket` — Port scanning & SSL certificate reading
- `concurrent.futures.ThreadPoolExecutor` — Parallel execution of all 7 scan modules

**Frontend**
- Pure HTML, CSS, JavaScript (no frameworks)
- `JetBrains Mono` + `Outfit` fonts (Google Fonts)
- Glassmorphism UI with animated glowing orbs
- Live hacker terminal animation during scanning

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or newer
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yug1204/domain-info.git
   cd domain-info
   ```

2. **Install dependencies**
   ```bash
   pip install fastapi uvicorn python-whois dnspython requests
   ```

3. **Run the server**
   ```bash
   python -m uvicorn main:app --reload
   ```

4. **Open in browser**
   ```
   http://127.0.0.1:8000
   ```

---

## 📡 API Reference

### `GET /api/scan?url={domain}`

Scans all 7 intel modules concurrently and returns the full reconnaissance report.

**Example Request:**
```
GET /api/scan?url=example.com
```

**Example Response:**
```json
{
  "domain": "example.com",
  "whois": { "registrar": "...", "creation_date": "...", ... },
  "dns": { "A": ["93.184.216.34"], "MX": [...], ... },
  "open_ports": [80, 443],
  "ssl": { "issuer": {...}, "notAfter": "...", ... },
  "headers": { "Server": "ECS", "Content-Type": "...", ... },
  "geolocation": { "country": "US", "city": "...", "isp": "...", ... },
  "robots_txt": { "found": true, "content": [...], "total_lines": 42 }
}
```

---

## 📁 Project Structure

```
domain-info/
├── main.py              # FastAPI backend — all 7 recon modules
└── static/
    ├── index.html       # Main UI layout + terminal element
    ├── script.js        # Scan logic, terminal animation, result rendering
    └── style.css        # Cyberpunk glassmorphism theme
```

---

## 🔐 Disclaimer

> This tool is built **strictly for educational and ethical security research purposes**.  
> Only scan domains you **own** or have **explicit written permission** to test.  
> Unauthorized reconnaissance of third-party systems may violate laws in your jurisdiction.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ by <a href="https://github.com/yug1204">yug1204</a>
</div>
