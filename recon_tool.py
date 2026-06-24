import json
import requests
import dns.resolver

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def normalize_domain(domain):
    domain = domain.strip().lower()

    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.strip(".")

    return domain


def get_dns_records(domain):
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = sorted([str(answer) for answer in answers])
        except Exception:
            results[record_type] = []

    return results


def create_requests_session():
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
        respect_retry_after_header=True
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)

    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


def get_crtsh_subdomains(domain):
    queries = [
        f"%.{domain}",
        domain
    ]

    headers = {
        "User-Agent": "PassiveReconTool/1.0"
    }

    session = create_requests_session()

    all_subdomains = set()
    errors = []

    for query in queries:
        try:
            response = session.get(
                "https://crt.sh/",
                params={
                    "q": query,
                    "output": "json"
                },
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:
                errors.append(
                    f"Query '{query}' returned HTTP {response.status_code}"
                )
                continue

            try:
                data = response.json()
            except ValueError:
                errors.append(
                    f"Query '{query}' did not return valid JSON"
                )
                continue

            if not isinstance(data, list):
                errors.append(
                    f"Query '{query}' returned unexpected data format"
                )
                continue

            for entry in data:
                names = entry.get("name_value", "").split("\n")

                for name in names:
                    clean_name = name.strip().lower()

                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]

                    if clean_name == domain or clean_name.endswith("." + domain):
                        all_subdomains.add(clean_name)

        except requests.exceptions.Timeout:
            errors.append(f"Query '{query}' timed out")

        except requests.exceptions.RequestException as error:
            errors.append(f"Query '{query}' failed: {error}")

    sorted_subdomains = sorted(all_subdomains)

    if sorted_subdomains:
        return {
            "source": "crt.sh",
            "status": "success",
            "count": len(sorted_subdomains),
            "subdomains": sorted_subdomains,
            "error": None,
            "warnings": errors,
            "message": "Certificate Transparency subdomains collected successfully."
        }

    return {
        "source": "crt.sh",
        "status": "error",
        "count": 0,
        "subdomains": [],
        "error": "; ".join(errors) if errors else "No data returned from crt.sh",
        "warnings": [],
        "message": "Certificate Transparency data could not be collected."
    }


def analyze_dns_security(dns_records):
    notes = []

    txt_records = " ".join(dns_records.get("TXT", [])).lower()

    if "v=spf1" in txt_records:
        notes.append("SPF record found.")
    else:
        notes.append("SPF record not found.")

    if "dmarc" in txt_records:
        notes.append("Possible DMARC-related TXT record found.")
    else:
        notes.append(
            "DMARC record not directly visible in root TXT records. "
            "Check _dmarc.domain separately."
        )

    mx_records = dns_records.get("MX", [])

    if mx_records:
        if "0 ." in mx_records:
            notes.append("Null MX record found. This domain may not accept email.")
        else:
            notes.append("MX records found. Mail provider may be identifiable.")
    else:
        notes.append("MX record not found.")

    return notes


def main():
    
    domain = input("Enter authorized domain: ")
    domain = normalize_domain(domain)

    if not domain:
        print("[-] Domain cannot be empty.")
        return

    print("\n[+] Collecting DNS records...")
    dns_records = get_dns_records(domain)

    print("\n[+] Collecting certificate transparency subdomains...")
    ct_result = get_crtsh_subdomains(domain)

    print("\n[+] Creating report data...")

    report = {
        "domain": domain,
        "mitre_mapping": {
            "T1590": "Gather Victim Network Information",
            "T1593": "Search Open Websites/Domains",
            "T1596": "Search Open Technical Databases"
        },
        "dns_records": dns_records,
        "certificate_transparency": {
            "source": ct_result["source"],
            "status": ct_result["status"],
            "count": ct_result["count"],
            "subdomains": ct_result["subdomains"][:50],
            "error": ct_result["error"],
            "warnings": ct_result["warnings"],
            "message": ct_result["message"]
        },
        "security_notes": analyze_dns_security(dns_records)
    }

    output_file = f"{domain}_recon_report.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved as {output_file}")


if __name__ == "__main__":
    main()