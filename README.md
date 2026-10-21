# RUK_HACKER

**Termux Security Toolkit — v1.0.0**

[![tests](https://github.com/Janrahat/RUK_HACKER/actions/workflows/tests.yml/badge.svg)](https://github.com/Janrahat/RUK_HACKER/actions/workflows/tests.yml)
[![release](https://img.shields.io/badge/release-v1.0.0-brightgreen)](https://github.com/Janrahat/RUK_HACKER/releases/tag/v1.0.0)
[![python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![deps](https://img.shields.io/badge/dependencies-0-success)](./requirements.txt)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![platform](https://img.shields.io/badge/platform-Termux%20%2F%20Android-black)](https://termux.dev/)

```
 ____  _   _ _  __   _   _    _    ____ _  _______ ____
|  _ \| | | | |/ /  | | | |  / \  / ___| |/ / ____|  _ \
| |_) | | | | ' /   | |_| | / _ \| |   | ' /|  _| | |_) |
|  _ <| |_| | . \   |  _  |/ ___ \ |___| . \| |___|  _ <
|_| \_\\___/|_|\_\  |_| |_/_/   \_\____|_|\_\_____|_| \_\
```

> ⚠️ **صرف قانونی استعمال / AUTHORISED USE ONLY**
> یہ ٹول صرف اُن سسٹمز پر استعمال کریں جو آپ کی ملکیت ہیں یا جن پر آپ کے پاس
> تحریری اجازت موجود ہے۔ بغیر اجازت اسکیننگ زیادہ تر ممالک میں جرم ہے۔
> This tool is for systems **you own** or have **written permission** to test.
> Unauthorised scanning is illegal in most jurisdictions.

---

## 🇵🇰 اردو حصہ

### یہ کیا ہے؟

**RUK_HACKER** ایک مکمل، پروفیشنل اور خودمختار سیکیورٹی ٹول ہے جو **صرف Termux
(Android)** کے لیے بنایا گیا ہے۔ یہ **Python 3 standard library** پر چلتا ہے —
کسی تھرڈ پارٹی پیکج، `pip install` یا **root** کی ضرورت نہیں۔

- 🎨 خوبصورت رنگین CLI بینر اور انٹرایکٹو مینو
- ⚡ subcommands بھی دستیاب (اسکرپٹنگ اور automation کے لیے)
- 🧵 تھریڈڈ اسکیننگ + rate limiting (نیٹ ورک پر دباؤ نہیں)
- 📄 JSON / HTML / TXT رپورٹ آؤٹ پٹ
- 🛡️ ہر رن پر قانونی وارننگ اور ایک بار کی منظوری (consent)

### خصوصیات

| فیچر | تفصیل |
|---|---|
| پورٹ اسکیننگ | TCP connect scan، سروس نام، بینر grab، خطرناک پورٹس کی نشاندہی |
| DNS | A, AAAA, MX, NS, TXT, SOA, CAA, SRV + reverse DNS + CNAME چین (خالص stdlib resolver) |
| WHOIS | ڈومین اور IP کے لیے port 43 کلائنٹ، referral chain فالو کرتا ہے |
| IP معلومات | ملک، شہر، ISP، ASN، reverse DNS، proxy/hosting flags |
| Web آڈٹ | HTTP ہیڈرز، security headers کی A+ سے F گریڈنگ، کوکیز، ٹیکنالوجی کی شناخت |
| SSL/TLS | سرٹیفکیٹ کی تفصیل، SAN، expiry، chain trust، cipher، SHA-256 fingerprint |
| Subdomain | DNS بروٹ فورس + crt.sh (Certificate Transparency)، wildcard DNS کا پتہ |
| Directory discovery | path discovery مع soft-404 detection (جھوٹے 200s فلٹر ہوتے ہیں) |
| System info | ڈیوائس، CPU، RAM، اسٹوریج، انٹرفیس، نصب پیکجز |

### انسٹالیشن (Termux)

```bash
# 1) Termux اپڈیٹ کریں
pkg update -y && pkg upgrade -y

# 2) Python انسٹال کریں
pkg install -y python

# 3) ریپو کلون کریں اور انسٹالر چلائیں
pkg install -y git
git clone https://github.com/Janrahat/RUK_HACKER.git
cd RUK_HACKER
bash install.sh
```

انسٹالر خود سے:
1. Python (3.8+) چیک کرتا ہے
2. اختیاری ٹولز (`openssl`, `dig`, `whois`, `nmap`, `jq`) پوچھ کر انسٹال کرتا ہے
3. `~/.local/share/ruk_hacker` میں فائلیں کاپی کرتا ہے
4. `ruk_hacker` اور `ruk` کمانڈز بناتا ہے
5. خود ٹیسٹ چلا کر تصدیق کرتا ہے

اگر سسٹم پیکجز نہیں چاہیے:

```bash
bash install.sh --no-deps
```

### استعمال — انٹرایکٹو مینو

بغیر کسی آرگیومینٹ کے چلائیں:

```bash
ruk_hacker
```

پہلی بار چلانے پر قانونی نوٹس آئے گا — ایک بار `y` دبا کر قبول کریں (یہ
`~/.ruk_hacker/config.json` میں محفوظ ہو جاتا ہے)۔

```
═══════════════════ » MAIN MENU ═══════════════════
  [ 1] Port scanner             TCP connect scan with banners + risk flags
  [ 2] DNS lookup               A/AAAA/MX/NS/TXT/SOA/CAA + CNAME chain
  [ 3] WHOIS                    Domain / IP registration data
  [ 4] IP intelligence          Geo, ISP, ASN, reverse DNS
  [ 5] Web header audit         Security headers, grade, cookies
  [ 6] TLS certificate          Validity, SAN, chain trust, cipher
  [ 7] Subdomain enumeration    DNS brute force + crt.sh
  [ 8] Path discovery           Directory/file discovery with soft-404 detection
  [ 9] System information       Device, CPU, memory, storage, packages
  [10] Quick recon              DNS + headers + TLS in one pass
  [11] Settings                 Timeouts, threads, rate limit, report folder
  [12] About / legal            Version and authorised-use notice
  [ 0] Exit

  ruk ❯
```

### استعمال — subcommands

#### `scan` — پورٹ اسکیننگ

```bash
ruk_hacker scan example.com -p top
ruk_hacker scan 192.168.1.1 -p 22,80,443,8000-8100 --threads 100 -b
ruk_hacker scan example.com -p all --timeout 2 --rate 200 --json
```

نمونہ آؤٹ پٹ:

```
──[ OPEN PORTS ]────────────────────────────────────────
  ┌──────┬─────────┬────────────────────────┬────────┐
  │ port │ service │ banner                 │ ms     │
  ├──────┼─────────┼────────────────────────┼────────┤
  │ 22   │ ssh     │ SSH-2.0-OpenSSH_9.6    │ 41.2   │
  │ 80   │ http    │ HTTP/1.1 200 OK        │ 38.7   │
  │ 443  │ https   │ HTTP/1.1 200 OK        │ 39.5   │
  └──────┴─────────┴────────────────────────┴────────┘
```

#### `ports` — تیز ٹاپ پورٹس اسکین

```bash
ruk_hacker ports example.com
```

#### `dns` — DNS ریکارڈز

```bash
ruk_hacker dns example.com
ruk_hacker dns example.com --record MX
ruk_hacker dns example.com --server 1.1.1.1
ruk_hacker dns 8.8.8.8          # reverse (PTR) lookup
```

نمونہ:

```
──[ A ]──────────────────────────────────────────────────
  ┌────────────────┬──────┐
  │ value          │ ttl  │
  ├────────────────┼──────┤
  │ 93.184.216.34  │ 3600 │
  └────────────────┴──────┘
```

#### `whois` — رجسٹریشن معلومات

```bash
ruk_hacker whois example.com
ruk_hacker whois 8.8.8.8
```

نمونہ:

```
──[ PARSED FIELDS ]─────────────────────────────────────
  │ registrar       │ RESERVED-Internet Assigned Numbers Authority │
  │ created         │ 1995-08-14T04:00:00Z                        │
  │ expires         │ 2027-08-13T04:00:00Z                        │
  │ nameservers     │ a.iana-servers.net, b.iana-servers.net      │

  ℹ expires in 295 days
```

#### `ip` — IP / geolocation

```bash
ruk_hacker ip 8.8.8.8
ruk_hacker ip example.com
ruk_hacker ip --me            # اپنا پبلک IP
```

#### `web` — ہیڈر اور سیکیورٹی آڈٹ

```bash
ruk_hacker web example.com
ruk_hacker web https://example.com --headers-only
ruk_hacker web https://self-signed.local -k     # سرٹیفکیٹ errors نظر انداز
```

نمونہ:

```
──[ SECURITY HEADERS ]──────────────────────────────────
  ┌───────────────────────────┬─────────┬──────────────────────────┐
  │ header                    │ state   │ value                    │
  ├───────────────────────────┼─────────┼──────────────────────────┤
  │ strict-transport-security │ missing │ —                        │
  │ content-security-policy   │ missing │ —                        │
  │ x-content-type-options    │ present │ nosniff                  │
  │ x-frame-options           │ present │ SAMEORIGIN               │
  └───────────────────────────┴─────────┴──────────────────────────┘

  security grade: D        score: 5/13
```

#### `ssl` — TLS سرٹیفکیٹ

```bash
ruk_hacker ssl example.com
ruk_hacker ssl example.com:8443
```

نمونہ:

```
──[ CERTIFICATE ]────────────────────────────────────────────
  │ subject cn    │ example.com                                │
  │ issuer        │ DigiCert Inc                               │
  │ days left     │ 87                                         │
  │ tls version   │ TLSv1.3                                    │
  │ chain trusted │ yes                                        │
  │ sha-256       │ 5f2a9c…9be1                                │
```

#### `subdomains` — سب ڈومین تلاش

```bash
ruk_hacker subdomains example.com
ruk_hacker subdomains example.com --no-crtsh
ruk_hacker subdomains example.com -w mylist.txt
```

نمونہ:

```
──[ RESOLVED HOSTS ]────────────────────────────────────────
  ┌──────────────┬────────────────┬───────┬──────────────┐
  │ subdomain    │ ips            │ cname │ source       │
  ├──────────────┼────────────────┼───────┼──────────────┤
  │ api.ex.com   │ 93.184.216.40  │ —     │ dns-brutef…  │
  │ www.ex.com   │ 93.184.216.34  │ —     │ crt.sh       │
  └──────────────┴────────────────┴───────┴──────────────┘
```

#### `dirscan` — ڈائریکٹری/پاتھ ڈسکوری

```bash
ruk_hacker dirscan https://example.com
ruk_hacker dirscan https://example.com -w paths.txt --codes 200,301,403
```

نمونہ:

```
──[ DISCOVERED ]────────────────────────────────────────────
  ┌──────────────┬────────┬───────┬──────────┐
  │ path         │ status │ bytes │ redirect │
  ├──────────────┼────────┼───────┼──────────┤
  │ /admin       │ 403    │ 287   │ —        │
  │ /robots.txt  │ 200    │ 132   │ —        │
  └──────────────┴────────┴───────┴──────────┘
```

#### `sysinfo` — سسٹم معلومات

```bash
ruk_hacker sysinfo
ruk_hacker sysinfo --json
```

#### `report` — محفوظ JSON سے رپورٹ بنائیں

```bash
ruk_hacker scan example.com -p top --out ~/scan.json
ruk_hacker report ~/scan.json --format html --out ~/scan.html
```

#### `update` / `version`

```bash
ruk_hacker update          # نیا ورژن چیک کریں
ruk_hacker update --apply  # git checkout کو fast-forward کریں
ruk_hacker version
```

#### `config` — ترتیبات

```bash
ruk_hacker config
ruk_hacker config --set threads=120
ruk_hacker config --set auto_save=true
ruk_hacker config --unset threads
```

### رپورٹس

```bash
ruk_hacker scan example.com --out report        # report.json
ruk_hacker scan example.com --out report --format html
ruk_hacker dirscan https://example.com --format all --out full
```

تمام رپورٹس `~/ruk_reports/` میں بھی محفوظ ہو سکتی ہیں (`auto_save` فعال ہو تو)۔

### انسٹال شدہ فائلز

```
~/.local/share/ruk_hacker/     ← پروگرام
$PREFIX/bin/ruk_hacker         ← لانچر
$PREFIX/bin/ruk                ← مختصر نام
~/.ruk_hacker/config.json      ← ترتیبات (chmod 600)
~/ruk_reports/                 ← رپورٹس
```

### اَن انسٹال

```bash
bash uninstall.sh             # ٹول ہٹائیں، رپورٹس محفوظ رہیں
bash uninstall.sh --dry-run   # صرف دکھائیں کیا حذف ہوگا
bash uninstall.sh --purge     # ترتیبات اور رپورٹس بھی حذف کریں
```

### ٹیسٹ چلانا

```bash
bash run_tests.sh
# یا
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

ٹیسٹس صرف localhost استعمال کرتے ہیں — کوئی بیرونی نیٹ ورک ٹریفک نہیں۔

---

## 🇬🇧 English

### What it is

**RUK_HACKER** is a complete, professional, self-contained security toolkit for
**Termux on Android**. It runs on the **Python 3 standard library only** — no
third-party packages, no `pip install`, and **no root required**.

- 🎨 Colourful CLI banner and interactive menu
- ⚡ Full subcommand interface for scripting and automation
- 🧵 Threaded scanning with rate limiting
- 📄 JSON / HTML / TXT report output
- 🛡️ Legal notice and one-time consent gate on first run

### Features

| Feature | Detail |
|---|---|
| Port scanning | TCP connect scan, service names, banner grab, risky-service flags |
| DNS | A, AAAA, MX, NS, TXT, SOA, CAA, SRV, reverse PTR, CNAME chain — pure-stdlib resolver |
| WHOIS | Domain and IP lookups over port 43, follows IANA referrals |
| IP intelligence | Country, city, ISP, ASN, reverse DNS, proxy/hosting indicators |
| Web audit | HTTP headers, security-header grading (A+ → F), cookies, tech fingerprints |
| TLS | Certificate subject/issuer, SAN, expiry, chain trust, cipher, SHA-256 |
| Subdomains | DNS brute force + crt.sh CT logs, wildcard-DNS detection |
| Path discovery | Directory/file enumeration with soft-404 filtering |
| System info | Device, CPU, memory, storage, interfaces, installed packages |

### Install (Termux)

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
git clone https://github.com/Janrahat/RUK_HACKER.git
cd RUK_HACKER
bash install.sh
```

The installer verifies Python 3.8+, offers the optional tools
(`openssl`, `dig`, `whois`, `nmap`, `jq`), copies the program to
`~/.local/share/ruk_hacker`, creates the `ruk_hacker` / `ruk` commands, and
runs a self-test.

Skip system packages with `bash install.sh --no-deps`.

### Usage — interactive menu

```bash
ruk_hacker
```

The first run shows the authorised-use notice; accepting it is stored in
`~/.ruk_hacker/config.json`.

### Usage — subcommands

```bash
# Ports
ruk_hacker scan example.com -p top
ruk_hacker scan 192.168.1.1 -p 22,80,443,8000-8100 --threads 100 -b
ruk_hacker ports example.com                       # quick top-ports alias

# DNS
ruk_hacker dns example.com
ruk_hacker dns example.com --record TXT
ruk_hacker dns 8.8.8.8                             # reverse lookup

# WHOIS / IP
ruk_hacker whois example.com
ruk_hacker ip 8.8.8.8
ruk_hacker ip --me

# Web / TLS
ruk_hacker web example.com
ruk_hacker web https://example.com --headers-only
ruk_hacker web https://self-signed.local -k
ruk_hacker ssl example.com
ruk_hacker ssl example.com:8443

# Enumeration
ruk_hacker subdomains example.com
ruk_hacker subdomains example.com -w list.txt --no-crtsh
ruk_hacker dirscan https://example.com -w paths.txt --codes 200,301,403

# Local + reports
ruk_hacker sysinfo --json
ruk_hacker scan example.com --out report --format all
ruk_hacker report report.json --format html --out report.html

# Maintenance
ruk_hacker update
ruk_hacker version
ruk_hacker config --set threads=120
```

### Sample output

```
$ ruk_hacker scan example.com -p top

──[ OPEN PORTS ]────────────────────────────────────────
  ┌──────┬─────────┬────────────────────────┬────────┐
  │ port │ service │ banner                 │ ms     │
  ├──────┼─────────┼────────────────────────┼────────┤
  │ 80   │ http    │ HTTP/1.1 200 OK        │ 38.7   │
  │ 443  │ https   │ HTTP/1.1 200 OK        │ 39.5   │
  └──────┴─────────┴────────────────────────┴────────┘
  ✔ No commonly risky services exposed.
```

```
$ ruk_hacker web example.com

──[ SECURITY HEADERS ]──────────────────────────────────
  │ strict-transport-security │ missing │ —        │
  │ content-security-policy   │ missing │ —        │
  │ x-content-type-options    │ present │ nosniff  │
  security grade: D        score: 5/13
```

```
$ ruk_hacker ssl example.com

──[ CERTIFICATE ]────────────────────────────────────────────
  │ subject cn    │ example.com     │
  │ issuer        │ DigiCert Inc    │
  │ days left     │ 87              │
  │ tls version   │ TLSv1.3         │
  │ chain trusted │ yes             │
```

### Options reference

| Flag | Applies to | Meaning |
|---|---|---|
| `-p, --port` | scan, ports | `top`, `all`, `22,80`, `1000-2000` |
| `-b, --banners` | scan, ports | grab service banners |
| `--threads N` | all scanners | worker threads (default 60) |
| `--rate N` | all scanners | max requests/second (0 = unlimited) |
| `-t, --timeout N` | all | per-request timeout in seconds |
| `--json` | all | machine-readable output on stdout |
| `--out PATH` | all | write a report file |
| `--format` | all | `json`, `html`, `txt`, `all` |
| `-w, --wordlist` | subdomains, dirscan | custom wordlist |
| `-k, --insecure` | web | ignore TLS certificate errors |
| `--accept-terms` | all | accept the legal notice for this run |

Environment variables: `RUK_ACCEPT_TERMS=1` (non-interactive consent),
`NO_COLOR=1` (plain output), `RUK_INSTALL_DIR` (custom install path).

### Reports

Every module can emit JSON, HTML, or plain text:

```bash
ruk_hacker scan example.com --out report --format all
# → report.json, report.html, report.txt
```

The HTML report is a standalone file — open it in any browser, no internet needed.

### Installed layout

```
~/.local/share/ruk_hacker/     ← program files
$PREFIX/bin/ruk_hacker         ← launcher
$PREFIX/bin/ruk                ← short alias
~/.ruk_hacker/config.json      ← settings (mode 600)
~/ruk_reports/                 ← saved reports
```

### Uninstall

```bash
bash uninstall.sh             # remove tool, keep reports & config
bash uninstall.sh --dry-run   # preview only
bash uninstall.sh --purge     # also delete config and reports
```

### Tests

```bash
bash run_tests.sh
# or
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

**71 tests pass** (49 unit + 22 smoke). Tests use localhost servers only —
no outbound network traffic.

| Suite | Covers |
|---|---|
| `tests/test_units.py` | port-spec parsing, target validation, DNS wire format (encode/parse/A/MX/TXT/NXDOMAIN), rate limiter, threading, grading, cookie analysis, WHOIS parsing, wordlists, all report renderers |
| `tests/test_smoke.py` | real TCP connect, HTTP client, header audit, directory discovery + soft-404 suppression, TLS certificate fetch/decode, CLI in a subprocess, report file generation |

### Project layout

```
RUK_HACKER/
├── ruk_hacker.py             # entry point
├── ruk_hacker/
│   ├── config.py             # settings, paths, legal notice
│   ├── ui.py                 # colours, banner, tables, prompts
│   ├── utils.py              # validation, ports, rate limiting, threading
│   ├── net.py                # TCP/HTTP/TLS primitives, DER decoding
│   ├── portscan.py           # port scanner + risk flags
│   ├── dnsclient.py          # pure-stdlib DNS client
│   ├── whois_lookup.py       # WHOIS over port 43
│   ├── ipinfo.py             # geo / ASN lookups
│   ├── webaudit.py           # header audit + TLS inspection
│   ├── dirscan.py            # path discovery with soft-404 detection
│   ├── subdomains.py         # subdomain enumeration
│   ├── sysinfo.py            # device information
│   ├── report.py             # JSON / HTML / TXT reports
│   ├── cli.py                # argparse + interactive menu
│   ├── updater.py            # version check / git pull
│   └── data/                 # bundled wordlists
├── tests/                    # unit + smoke tests
├── .github/workflows/        # CI (tests on 3.9–3.12)
├── install.sh / uninstall.sh
├── run_tests.sh
├── CHANGELOG.md
├── LICENSE
└── README.md
```

### Design notes

- **Zero dependencies** — stdlib only, so it keeps working after every Termux update.
- **Safety first** — every run is rate-limited, thread-capped, and timeouts are enforced.
- **Honest results** — soft-404 pages and wildcard DNS are detected and filtered so
  the report doesn't invent findings.
- **No destructive actions** — the tool only reads; it never writes to a target.

### Legal

Provided under the MIT License (see `LICENSE`). The authors accept **no
liability** for misuse. You are solely responsible for complying with the laws
of your jurisdiction and for obtaining permission before testing any system.

---

**RUK_HACKER v1.0.0** · made for Termux · authorised testing only
