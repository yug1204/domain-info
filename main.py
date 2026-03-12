from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import whois
import dns.resolver
import socket
import ssl
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

app = FastAPI(title="Domain Recon API")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

def get_domain_from_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def get_whois(domain):
    try:
        w = whois.whois(domain)
        res = dict(w)
        for k, v in res.items():
            if hasattr(v, 'isoformat'):
                res[k] = v.isoformat()
            elif isinstance(v, list):
                res[k] = [x.isoformat() if hasattr(x, 'isoformat') else x for x in v]
        return res
    except Exception as e:
        return {"error": str(e)}

def get_dns(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for qtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, qtype)
            records[qtype] = [rdata.to_text() for rdata in answers]
        except Exception:
            pass
    return records

def get_ports(domain):
    ports = [21, 22, 25, 53, 80, 443, 8080, 8443, 3306]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def get_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                return {
                    "issuer": issuer,
                    "subject": subject,
                    "version": cert.get('version'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter')
                }
    except Exception as e:
        return {"error": str(e)}

def get_headers(domain):
    try:
        url = f"https://{domain}"
        response = requests.head(url, timeout=3, allow_redirects=True)
        return dict(response.headers)
    except Exception as e:
        try:
            url = f"http://{domain}"
            response = requests.head(url, timeout=3, allow_redirects=True)
            return dict(response.headers)
        except Exception as e2:
            return {"error": str(e2)}

@app.get("/api/scan")
def scan_domain(url: str):
    domain = get_domain_from_url(url)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_whois = executor.submit(get_whois, domain)
        future_dns = executor.submit(get_dns, domain)
        future_ports = executor.submit(get_ports, domain)
        future_ssl = executor.submit(get_ssl, domain)
        future_headers = executor.submit(get_headers, domain)

    return {
        "domain": domain,
        "whois": future_whois.result(),
        "dns": future_dns.result(),
        "open_ports": future_ports.result(),
        "ssl": future_ssl.result(),
        "headers": future_headers.result()
    }
