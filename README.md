<img width="872" height="249" alt="Screenshot 2026-06-24 at 13 11 12" src="https://github.com/user-attachments/assets/1ac59853-85e8-4b7e-9d3e-cad3cec4ec66" />

# Passive Recon Tool

This project is a Python-based tool designed to perform basic **passive reconnaissance** on an authorized domain. The script collects DNS records, attempts to retrieve subdomains from Certificate Transparency data, generates basic security notes, and saves the results as a JSON report.

> Use this tool only on domains you own or have explicit permission to test.

## Features

* Collects A, AAAA, MX, NS, and TXT DNS records.
* Queries `crt.sh` for Certificate Transparency data.
* Extracts discovered subdomains.
* Generates basic security notes for SPF, DMARC, and MX records.
* Includes a simple MITRE ATT&CK Reconnaissance mapping.
* Saves results in JSON format.

## Project Structure

```text
Recon_passive_tool/
├── recon_tool.py
├── requirements.txt
├── example.com_recon_report.json
└── README.md
```

## Requirements

This project requires the following Python packages:

```txt
requests
dnspython
```

## Installation

First, clone the repository:

```bash
git clone https://github.com/username/Recon_passive_tool.git
cd Recon_passive_tool
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the script with:

```bash
python recon_tool.py
```

When prompted, enter an authorized domain:

```bash
Enter authorized domain: example.com
```

After running, the script will:

1. Collect DNS records.
2. Attempt to collect subdomains from Certificate Transparency data.
3. Generate basic security notes.
4. Create a JSON report file.

## Example Output

```json
{
    "domain": "example.com",
    "mitre_mapping": {
        "T1590": "Gather Victim Network Information",
        "T1593": "Search Open Websites/Domains",
        "T1596": "Search Open Technical Databases"
    },
    "dns_records": {
        "A": [
            "104.20.23.154",
            "172.66.147.243"
        ],
        "AAAA": [
            "2606:4700:10::6814:179a",
            "2606:4700:10::ac42:93f3"
        ],
        "MX": [
            "0 ."
        ],
        "NS": [
            "hera.ns.cloudflare.com.",
            "elliott.ns.cloudflare.com."
        ],
        "TXT": [
            "\"v=spf1 -all\"",
            "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\""
        ]
    },
    "certificate_transparency_subdomains": [
        "Could not fetch certificate data: HTTPSConnectionPool(host='crt.sh', port=443): Read timed out. (read timeout=15)"
    ],
    "security_notes": [
        "SPF record found.",
        "DMARC record not directly visible in root TXT records. Check _dmarc.domain separately.",
        "MX records found. Mail provider may be identifiable."
    ]
}
```

The generated report is saved using the following filename format:

```text
example.com_recon_report.json
```

## MITRE ATT&CK Mapping

| Technique | Description                       |
| --------- | --------------------------------- |
| T1590     | Gather Victim Network Information |
| T1593     | Search Open Websites/Domains      |
| T1596     | Search Open Technical Databases   |

## Security Notes

The script performs the following basic checks:

* Checks whether an SPF record exists in TXT records.
* Checks whether a DMARC-related value appears in root TXT records.
* Reports whether MX records exist, since mail infrastructure may be identifiable.

DMARC records are usually published under the following format instead of the root TXT records:

```text
_dmarc.example.com
```

For this reason, the script currently provides only a basic DMARC-related note.

## Limitations

* If `crt.sh` is unavailable or times out, subdomain data may not be retrieved.
* DMARC analysis is limited to root TXT records.
* The script does not perform active scanning, port scanning, or exploitation.
* Results depend on publicly available passive sources and DNS responses.
* Certificate Transparency results are limited to the first 50 subdomains.

## Ethical Use

This tool should only be used in the following cases:

* On domains you own,
* On systems where you have written authorization,
* In educational, lab, or security awareness environments.

Unauthorized reconnaissance may lead to legal and ethical consequences. The user is fully responsible for how they use this tool.

## License

This project is shared for educational and security research purposes. Users are responsible for how they use it.





_tr_

Bu proje, yetkili olunan bir domain üzerinde temel **pasif keşif** işlemleri yapmak için geliştirilmiş Python tabanlı bir araçtır. Script; DNS kayıtlarını toplar, Certificate Transparency kayıtları üzerinden subdomain bilgisi elde etmeye çalışır, temel güvenlik notları üretir ve sonuçları JSON formatında raporlar.

> Bu araç yalnızca sahibi olduğunuz veya test etmek için açık izin aldığınız domainlerde kullanılmalıdır.

## Özellikler

* A, AAAA, MX, NS ve TXT DNS kayıtlarını toplar.
* `crt.sh` üzerinden Certificate Transparency kayıtlarını sorgular.
* Bulunan subdomainleri listeler.
* SPF, DMARC ve MX kayıtları hakkında temel güvenlik notları üretir.
* MITRE ATT&CK Reconnaissance teknikleriyle basit eşleştirme içerir.
* Sonuçları JSON dosyası olarak kaydeder.

## Proje Yapısı

```text
Recon_passive_tool/
├── recon_tool.py
├── requirements.txt
├── example.com_recon_report.json
└── README.md
```

## Gereksinimler

Bu proje aşağıdaki Python paketlerine ihtiyaç duyar:

```txt
requests
dnspython
```

## Kurulum

Öncelikle projeyi klonlayın:

```bash
git clone https://github.com/kullanici-adi/Recon_passive_tool.git
cd Recon_passive_tool
```

Gerekli bağımlılıkları yükleyin:

```bash
pip install -r requirements.txt
```

## Kullanım

Scripti çalıştırmak için:

```bash
python recon_tool.py
```

Program çalıştığında sizden yetkili olduğunuz domaini girmeniz istenir:

```bash
Enter authorized domain: example.com
```

Script çalıştıktan sonra aşağıdaki işlemleri gerçekleştirir:

1. DNS kayıtlarını toplar.
2. Certificate Transparency kayıtlarından subdomain bilgisi almaya çalışır.
3. Temel güvenlik notları oluşturur.
4. JSON formatında rapor dosyası üretir.

## Örnek Çıktı

```json
{
    "domain": "example.com",
    "mitre_mapping": {
        "T1590": "Gather Victim Network Information",
        "T1593": "Search Open Websites/Domains",
        "T1596": "Search Open Technical Databases"
    },
    "dns_records": {
        "A": [
            "104.20.23.154",
            "172.66.147.243"
        ],
        "AAAA": [
            "2606:4700:10::6814:179a",
            "2606:4700:10::ac42:93f3"
        ],
        "MX": [
            "0 ."
        ],
        "NS": [
            "hera.ns.cloudflare.com.",
            "elliott.ns.cloudflare.com."
        ],
        "TXT": [
            "\"v=spf1 -all\"",
            "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\""
        ]
    },
    "certificate_transparency_subdomains": [
        "Could not fetch certificate data: HTTPSConnectionPool(host='crt.sh', port=443): Read timed out. (read timeout=15)"
    ],
    "security_notes": [
        "SPF record found.",
        "DMARC record not directly visible in root TXT records. Check _dmarc.domain separately.",
        "MX records found. Mail provider may be identifiable."
    ]
}
```

Oluşturulan rapor dosyası aşağıdaki isim formatıyla kaydedilir:

```text
example.com_recon_report.json
```

## MITRE ATT&CK Eşleştirmesi

| Teknik | Açıklama                          |
| ------ | --------------------------------- |
| T1590  | Gather Victim Network Information |
| T1593  | Search Open Websites/Domains      |
| T1596  | Search Open Technical Databases   |

## Güvenlik Notları

Script aşağıdaki temel kontrolleri yapar:

* TXT kayıtları içinde SPF kaydı olup olmadığını kontrol eder.
* Root TXT kayıtlarında DMARC ile ilişkili bir ifade olup olmadığını kontrol eder.
* MX kayıtları varsa mail altyapısının tanımlanabilir olabileceğini belirtir.

DMARC kayıtları genellikle root TXT kayıtlarında değil, aşağıdaki formatta bulunur:

```text
_dmarc.example.com
```

Bu nedenle script, DMARC kontrolü için yalnızca temel bir uyarı üretir.

## Sınırlamalar

* `crt.sh` yanıt vermezse veya zaman aşımına uğrarsa subdomain verisi alınamayabilir.
* DMARC kontrolü yalnızca root TXT kayıtları üzerinden yapılır.
* Script aktif tarama, port tarama veya exploit denemesi yapmaz.
* Elde edilen sonuçlar pasif kaynaklara ve DNS yanıtlarına bağlıdır.
* Certificate Transparency sonuçları ilk 50 subdomain ile sınırlandırılmıştır.

## Etik Kullanım

Bu araç yalnızca aşağıdaki durumlarda kullanılmalıdır:

* Kendi domainleriniz üzerinde,
* Yazılı izin alınmış sistemlerde,
* Eğitim, laboratuvar veya güvenlik farkındalığı çalışmalarında.

İzinsiz keşif faaliyetleri yasal ve etik sorunlara yol açabilir. Kullanıcı, aracı kullanırken tüm sorumluluğu kendisi üstlenir.

## Lisans

Bu proje eğitim ve güvenlik araştırmaları amacıyla paylaşılmıştır. Kullanım sorumluluğu kullanıcıya aittir.
