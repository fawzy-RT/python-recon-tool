#!/usr/bin/env python3

import sys
import socket
import requests
import re
import subprocess
import hashlib
from urllib.parse import urlparse

G = '\033[92m'
Y = '\033[93m'
C = '\033[96m'
R = '\033[91m'
M = '\033[95m'
N = '\033[0m'

if len(sys.argv) < 2:
    print("Usage: python recon.py <domain/email/username/IP>")
    sys.exit(1)

raw = sys.argv[1].strip().lower()

if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw):
    target_type, target = 'ip', raw
elif '@' in raw:
    target_type, target = 'email', raw
elif '.' in raw:
    if raw.startswith(('http://', 'https://')):
        raw = urlparse(raw).netloc.split(':')[0]
    target_type, target = 'domain', raw
else:
    target_type, target = 'username', raw

print(f"\n{C}[+] Target: {target}  ({target_type}){N}\n")

# Domain recon
if target_type == 'domain':
    print(f"{M}[1] DNS Resolution{N}")
    try:
        ip = socket.gethostbyname(target)
        print(f"  {G}+{N} IP: {ip}")
        try:
            host = socket.gethostbyaddr(ip)
            print(f"  {G}+{N} Reverse DNS: {host[0]}")
        except:
            print(f"  {Y}!{N} No reverse DNS")
        for t in ['MX', 'NS', 'TXT']:
            try:
                out = subprocess.run(['host', '-t', t, target], capture_output=True, text=True, timeout=5)
                for line in out.stdout.split('\n'):
                    if 'handled by' in line or 'name server' in line.lower() or 'descriptive text' in line:
                        txt = line.split('descriptive text')[-1].strip().strip('"')[:80] if 'descriptive' in line else line.strip()
                        print(f"  {G}+{N} {t}: {txt}")
            except:
                pass
    except socket.gaierror:
        print(f"  {R}x{N} Domain not found")
        sys.exit(1)

    print(f"\n{M}[2] WHOIS Lookup{N}")
    try:
        out = subprocess.run(['whois', target], capture_output=True, text=True, timeout=15)
        seen = set()
        for line in out.stdout.split('\n'):
            for kw in ['Domain Name:', 'Registrar:', 'Creation Date:', 'Registry Expiry Date:',
                       'Name Server:', 'Registrant Organization:', 'Registrant Country:']:
                if line.strip().startswith(kw):
                    clean = line.strip().lower()
                    if clean not in seen:
                        seen.add(clean)
                        print(f"  {G}+{N} {line.strip()}")
                    break
    except:
        print(f"  {Y}!{N} WHOIS failed")

    print(f"\n{M}[3] Subdomain Enumeration{N}")
    subs = ['www','mail','ftp','admin','api','dev','test','blog','shop','login','dashboard',
            'cpanel','vpn','git','wiki','cloud','app','help','support','cdn','docs','staging','beta','ns1','ns2']
    for sub in subs:
        try:
            socket.gethostbyname(f"{sub}.{target}")
            print(f"  {G}+{N} {sub}.{target}")
        except:
            pass

    print(f"\n{M}[4] HTTP Headers & Server Info{N}")
    for proto in ['https://', 'http://']:
        try:
            r = requests.get(f"{proto}{target}", timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            print(f"  {G}+{N} Status: {r.status_code} ({r.url})")
            for h in ['Server', 'X-Powered-By', 'X-Frame-Options', 'Strict-Transport-Security',
                       'Content-Security-Policy', 'X-Content-Type-Options', 'Set-Cookie']:
                if h in r.headers:
                    print(f"  {G}+{N} {h}: {r.headers[h][:80]}")
            break
        except:
            continue

    print(f"\n{M}[5] Technology Detection{N}")
    try:
        r = requests.get(f"https://{target}", timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        h = r.text.lower()
        hs = str(r.headers).lower()
        if 'wp-' in h: print(f"  {G}+{N} CMS: WordPress")
        if 'drupal' in h or 'drupal.settings' in h: print(f"  {G}+{N} CMS: Drupal")
        if 'joomla' in h: print(f"  {G}+{N} CMS: Joomla")
        if 'react' in h: print(f"  {G}+{N} JS: React")
        if 'angular' in h or 'ng-version' in h: print(f"  {G}+{N} JS: Angular")
        if 'jquery' in h: print(f"  {G}+{N} JS: jQuery")
        if 'vue.' in h: print(f"  {G}+{N} JS: Vue.js")
        if 'bootstrap' in h: print(f"  {G}+{N} CSS: Bootstrap")
        if 'cloudflare' in h or 'cloudflare' in hs: print(f"  {G}+{N} WAF: Cloudflare")
        if 'sucuri' in h or 'sucuri' in hs: print(f"  {G}+{N} WAF: Sucuri")
    except:
        pass

    print(f"\n{M}[6] Directory Fuzzing{N}")
    paths = ['/admin','/login','/wp-admin','/dashboard','/config','/backup','/.env','/robots.txt',
             '/sitemap.xml','/api','/graphql','/phpmyadmin','/uploads','/.well-known/security.txt',
             '/swagger.json','/phpinfo.php','/crossdomain.xml','/composer.json']
    base_size = 0
    try:
        base = requests.get(f"https://{target}", timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=False)
        base_size = len(base.text)
    except:
        pass
    for path in paths:
        for proto in ['https://', 'http://']:
            try:
                r = requests.get(f"{proto}{target}{path}", timeout=3, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=False)
                if r.status_code == 200 and len(r.text) != base_size:
                    print(f"  {G}+{N} 200 {path}")
                elif r.status_code in [401, 403]:
                    print(f"  {G}+{N} {r.status_code} {path} (auth)")
                break
            except:
                continue

    print(f"\n{M}[7] Page Content & Emails{N}")
    try:
        r = requests.get(f"https://{target}", timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        title = re.findall(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
        if title: print(f"  {G}+{N} Title: {title[0].strip()[:80]}")
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text))
        for e in sorted(emails)[:8]: print(f"  {G}+{N} Email: {e}")
        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', r.text)
        print(f"  {G}+{N} Links found: {len(links)}")
    except:
        pass

    print(f"\n{M}[8] Google Dorks{N}")
    for i, d in enumerate([
        f"site:{target}", f"site:{target} intitle:\"index of\"",
        f"site:{target} inurl:admin | inurl:login",
        f"site:{target} ext:sql | ext:bak | ext:old",
        f"site:{target} \"password\" | \"secret\" | \"api_key\"",
        f"site:pastebin.com {target}", f"site:github.com {target}"
    ], 1):
        print(f"  [{i}] {d}")

# Email mode
elif target_type == 'email':
    username, email_domain = target.split('@')
    print(f"{M}[1] Email Info{N}")
    print(f"  {G}+{N} Username: {username}")
    print(f"  {G}+{N} Domain: {email_domain}")
    email_hash = hashlib.md5(target.lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://www.gravatar.com/{email_hash}.json", timeout=3)
        if r.status_code == 200:
            print(f"  {G}+{N} Gravatar: {r.json().get('entry',[{}])[0].get('displayName','Unknown')}")
    except:
        print(f"  {Y}!{N} No Gravatar")
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{email_hash[:5]}", timeout=5)
        if r.status_code == 200: print(f"  {G}+{N} HIBP: API OK")
    except:
        pass
    print(f"\n{C}--- Domain Recon on: {email_domain} ---{N}\n")
    target = email_domain
    try:
        ip = socket.gethostbyname(email_domain)
        print(f"  {G}+{N} IP: {ip}")
        for t in ['MX','NS','TXT']:
            try:
                out = subprocess.run(['host','-t',t,email_domain], capture_output=True, text=True, timeout=5)
                for line in out.stdout.split('\n'):
                    if 'handled by' in line or 'name server' in line.lower() or 'descriptive text' in line:
                        print(f"  {G}+{N} {t}: {line.strip()[:80]}")
            except:
                pass
    except:
        print(f"  {Y}!{N} DNS failed")
    try:
        out = subprocess.run(['whois', email_domain], capture_output=True, text=True, timeout=15)
        seen = set()
        for line in out.stdout.split('\n'):
            for kw in ['Domain Name:', 'Registrar:', 'Creation Date:', 'Registry Expiry Date:', 'Name Server:']:
                if line.strip().startswith(kw):
                    clean = line.strip().lower()
                    if clean not in seen:
                        seen.add(clean); print(f"  {G}+{N} {line.strip()}")
                    break
    except:
        print(f"  {Y}!{N} WHOIS failed")

# Username mode
elif target_type == 'username':
    print(f"{M}[1] Username Search Online{N}")
    for site, url in {'GitHub':f'https://github.com/{target}','Twitter/X':f'https://x.com/{target}',
                       'Instagram':f'https://www.instagram.com/{target}/','Reddit':f'https://www.reddit.com/user/{target}/',
                       'YouTube':f'https://www.youtube.com/@{target}'}.items():
        try:
            r = requests.get(url, timeout=3, headers={'User-Agent':'Mozilla/5.0'}, allow_redirects=False)
            if r.status_code == 200: print(f"  {G}+{N} {site}: {url}")
        except:
            pass

# IP mode
elif target_type == 'ip':
    print(f"{M}[1] IP Geolocation{N}")
    try:
        r = requests.get(f"http://ip-api.com/json/{target}", timeout=5)
        data = r.json()
        if data.get('status') == 'success':
            for k in ['country','regionName','city','isp','org','as']:
                if data.get(k): print(f"  {G}+{N} {k.replace('_',' ').title()}: {data[k]}")
        else:
            print(f"  {Y}!{N} Private IP or failed")
    except:
        print(f"  {Y}!{N} Geo-IP error")

print(f"\n{C}{'='*55}{N}")
print(f"{G}[+] Done — {target} ({target_type}){N}")
print(f"{C}{'='*55}{N}")
