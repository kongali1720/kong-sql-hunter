import requests
import urllib.parse
from termcolor import cprint

def load_payloads():
    with open("payloads.txt", "r") as file:
        return [line.strip() for line in file.readlines()]

def scan_url(url, payloads):
    vulnerable = False
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        cprint("[!] URL tidak memiliki parameter untuk diuji!", "yellow")
        return False

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
                    vulnerable = True
                    break
            except Exception as e:
                cprint(f"[x] Error mengakses: {test_url}", "magenta")
                continue

    if not vulnerable:
        cprint("[✓] Tidak ditemukan SQLi pada parameter yang diuji.", "green")
    return vulnerable

if __name__ == "__main__":
    cprint("=== KONGALI1720 SQLI SCANNER ===", "cyan", attrs=["bold"])
    target = input("Masukkan URL target (dengan parameter): ").strip()
    payloads = load_payloads()
    scan_url(target, payloads)
