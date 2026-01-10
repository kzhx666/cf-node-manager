# -*- coding: utf-8 -*-
import json, base64, urllib.parse, os, copy, datetime, re, random, threading, time, socket, shutil, glob, asyncio, logging, zipfile, io, binascii, ssl
from flask import Flask, request, render_template, render_template_string, Response, jsonify, send_file, redirect, make_response, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import deque

try: import requests; import aiohttp; import yaml; import geoip2.database
except: pass

app = Flask(__name__)
try: app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
except: pass

WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "admin")
LOGIN_PATH = "admin_login"
DATA_DIR = "/app/data"
APP_VERSION = "v42.40-hy2mport-anytls-shadowtls-naive"
DATA_FILE = os.path.join(DATA_DIR, "data.json")
BACKUP_FILE = os.path.join(DATA_DIR, "data.json.bak")
CACHE_FILE = os.path.join(DATA_DIR, "domain_cache.json")
GEOIP_DB = os.path.join(DATA_DIR, "Country.mmdb")
LOG_FILE = os.path.join(DATA_DIR, "app.log")

MAX_NODES_OUTPUT = 5000
DATA_LOCK = threading.Lock()
IS_SYNCING = False 
SUB_TOKEN_CHECK = True
IP_SEPARATOR = "##### ⬇️ 自动获取 (请写在横线上面) ⬇️ #####"
DEFAULT_IPS = "104.16.1.1\n172.67.1.1"

if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR, exist_ok=True)

def write_log(msg):
    t = datetime.datetime.now().strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {msg}", flush=True)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f: f.write(f"[{t}] {msg}\n")
    except: pass

def init_geoip():
    if not os.path.exists(GEOIP_DB) and requests:
        try:
            r = requests.get("https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb", stream=True, timeout=60)
            if r.status_code == 200:
                with open(GEOIP_DB, 'wb') as f: f.write(r.content)
        except: pass
threading.Thread(target=init_geoip).start()

DOMAIN_CACHE = {}
if os.path.exists(CACHE_FILE):
    try: 
        with open(CACHE_FILE, 'r') as f: DOMAIN_CACHE = json.load(f)
    except: pass
def save_cache():
    try: 
        with open(CACHE_FILE, 'w') as f: json.dump(DOMAIN_CACHE, f)
    except: pass

def load_data():
    default_conf = {"ips": DEFAULT_IPS, "remote_subs": [], "cached_nodes": [], "cf_api_url": "", "custom_doh": "", "max_ips_per_node": 0, "clash_tpl": "proxies:\n#PLACEHOLDER#", "last_sync": int(time.time()), "config": { "interval": 14400, "threads": 8, "timeout": 20, "ua": "v2rayNG/1.8.5", "sub_token": WEB_PASSWORD, "custom_groups": "snip, work" }}
    with DATA_LOCK:
        if not os.path.exists(DATA_FILE):
            if os.path.exists(BACKUP_FILE): shutil.copy2(BACKUP_FILE, DATA_FILE)
            else: return default_conf
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                d = json.load(f)
                if "config" not in d: d["config"] = default_conf["config"]
                if "ips" not in d: d["ips"] = default_conf["ips"]
                return d
        except Exception as e:
            write_log(f"Load Error: {e}")
            if os.path.exists(BACKUP_FILE):
                try: shutil.copy2(BACKUP_FILE, DATA_FILE); return json.load(open(DATA_FILE))
                except: pass
            return default_conf

def save_data(data):
    with DATA_LOCK:
        try:
            if os.path.exists(DATA_FILE): shutil.copy2(DATA_FILE, BACKUP_FILE)
            tmp = DATA_FILE + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, DATA_FILE)
        except Exception as e: write_log(f"Save Error: {e}")

SMART_REGION_MAP = {
    r"(?i)(美国|美|States|America|\bUS\b)": "🇺🇸 美国",
    r"(?i)(香港|港|HongKong|\bHK\b)": "🇭🇰 香港",
    r"(?i)(日本|日|Japan|\bJP\b)": "🇯🇵 日本",
    r"(?i)(新加坡|新|Singapore|\bSG\b)": "🇸🇬 新加坡",
    r"(?i)(台湾|台|Taiwan|\bTW\b)": "🇹🇼 台湾",
    r"(?i)(韩国|韩|Korea|\bKR\b)": "🇰🇷 韩国",
    r"(?i)(英国|英|United Kingdom|\bUK\b)": "🇬🇧 英国",
    r"(?i)(德国|德|Germany|\bDE\b)": "🇩🇪 德国",
    r"(?i)(法国|法|France|\bFR\b)": "🇫🇷 法国",
    r"(?i)(俄罗斯|俄|Russia|\bRU\b)": "🇷🇺 俄罗斯",
    r"(?i)(加拿大|加|Canada|\bCA\b)": "🇨🇦 加拿大",
    r"(?i)(澳大利亚|澳|Australia|\bAU\b)": "🇦🇺 澳大利亚",
    r"(?i)(印度|印|India|\bIN\b)": "🇮🇳 印度",
    r"(?i)(荷兰|荷|Netherlands|\bNL\b)": "🇳🇱 荷兰",
    r"(?i)(土耳其|土|Turkey|\bTR\b)": "🇹🇷 土耳其",
    r"(?i)(巴西|巴|Brazil|\bBR\b)": "🇧🇷 巴西",
    r"(?i)(阿根廷|Argentina|\bAR\b)": "🇦🇷 阿根廷",
    r"(?i)(越南|Vietnam|\bVN\b)": "🇻🇳 越南",
    r"(?i)(泰国|泰|Thailand|\bTH\b)": "🇹🇭 泰国",
    r"(?i)(菲律宾|Philippines|\bPH\b)": "🇵🇭 菲律宾",
    r"(?i)(马来西亚|Malaysia|\bMY\b)": "🇲🇾 马来西亚",
    r"(?i)(印度尼西亚|Indonesia|\bID\b)": "🇮🇩 印尼",
}

def safe_b64decode(s):
    if not s: return b""
    s = s.strip().replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4))

def parse_ports_spec(spec: str):
    """Parse port range list like '443', '5000-6000', '443,5000-6000', '443/5000-6000' into ['443','5000-6000']"""
    if not spec:
        return []
    spec = str(spec).strip()
    if not spec:
        return []
    # mihomo uses '/' as separator for multi ranges; also accept ',' and ';'
    spec = spec.replace("/", ",").replace(";", ",")
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    return parts

def join_ports_spec(parts):
    parts = [str(p).strip() for p in (parts or []) if str(p).strip()]
    return ",".join(parts)

async def resolve_domain_to_ip(domain):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain): return domain
    if domain in DOMAIN_CACHE: return DOMAIN_CACHE[domain]
    if not aiohttp: return None
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=3) as r:
                js = await r.json(); ip = js['Answer'][0]['data']; DOMAIN_CACHE[domain] = ip; return ip
    except: pass
    return None

def get_flag(ip):
    if not geoip2 or not os.path.exists(GEOIP_DB): return ""
    try:
        iso = geoip2.database.Reader(GEOIP_DB).country(ip).country.iso_code
        flags = {"US":"🇺🇸","HK":"🇭🇰","JP":"🇯🇵","SG":"🇸🇬","TW":"🇹🇼","KR":"🇰🇷","CN":"🇨🇳","GB":"🇬🇧","DE":"🇩🇪","FR":"🇫🇷","RU":"🇷🇺","CA":"🇨🇦","AU":"🇦🇺"}
        return flags.get(iso, iso)
    except: return ""

async def smart_identify_region(node, tag):
    name = node['name']; server = node['server']
    for p, f in SMART_REGION_MAP.items():
        if re.search(p, tag or name): return f"{f.split(' ')[0]} {tag or name}"
    try:
        ip = await resolve_domain_to_ip(server); flag = get_flag(ip)
        if flag: return f"{flag} {tag or name}"
    except: pass
    return f"{tag}" if tag else "Node"

def parse_traffic_info(header_str):
    if not header_str: return None
    try:
        info = dict(re.findall(r'(\w+)=(\d+)', header_str))
        if not info: return None
        u=int(info.get('upload',0)); d=int(info.get('download',0)); t=int(info.get('total',0)); e=int(info.get('expire',0))
        fmt = lambda n: f"{n/1073741824:.1f}GB"
        pct = min(100, int((u+d)/t*100)) if t>0 else 0
        exp = f"剩{(datetime.datetime.fromtimestamp(e)-datetime.datetime.now()).days}天" if e>0 else "无限期"
        return {"used": fmt(u+d), "total": fmt(t), "percent": pct, "expire": exp, "color": "#28a745" if pct < 80 else "#dc3545"}
    except: return None

async def fetch_single_url(session, url, timeout):
    try:
        async with session.get(url, timeout=timeout, ssl=False) as r:
            if r.status == 200:
                text = await r.text()
                info = parse_traffic_info(r.headers.get('Subscription-Userinfo', ''))
                return text, info
    except: pass
    return None, None

def decode_sub_content(content):
    content = content.strip()
    if ('\n' not in content and '\r' not in content) and any(content.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'anytls://', 'shadowtls://', 'stls://', 'naive+https://', 'naive+quic://', 'naive://']):
        return parse_uri_list([content])
    try:
        if yaml and ("proxies:" in content or "Proxy:" in content):
            try: return [clash_to_internal(p) for p in (yaml.safe_load(content).get('proxies') or [])]
            except: pass
        try: return parse_uri_list(base64.b64decode(content + '='*(-len(content)%4)).decode('utf-8', 'ignore').splitlines())
        except: return parse_uri_list(content.splitlines())
    except: return []

def parse_uri_list(lines): return [n for n in (parse_uri(l.strip()) for l in lines) if n]

def parse_uri(uri):
    if not uri:
        return None
    try:
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)

        # Base (do NOT eagerly access p.port for schemes that may carry multi-port)
        name = urllib.parse.unquote(p.fragment or "")
        server = p.hostname
        try:
            base_port = p.port
        except:
            base_port = None
        b = {
            "name": name,
            "server": server,
            "port": base_port,
            "uuid": p.username,
            "password": p.password
        }

        if p.scheme == "vless":
            b.update({
                'type': 'vless',
                'network': q.get('type', ['tcp'])[0],
                'tls': q.get('security', [''])[0] in ['tls', 'reality'],
                'reality': q.get('security', [''])[0] == 'reality',
                'flow': q.get('flow', [''])[0],
                'sni': q.get('sni', [''])[0],
            })
            if b['reality']:
                b.update({
                    'pbk': q.get('pbk', [''])[0],
                    'sid': q.get('sid', [''])[0],
                    'fp': q.get('fp', ['chrome'])[0],
                })
            if q.get('insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1':
                b['skip-cert-verify'] = True
            if q.get('fp'):
                b['fp'] = q.get('fp')[0]
            if b['network'] == 'ws':
                b.update({'ws-path': q.get('path', ['/'])[0], 'ws-host': q.get('host', [''])[0]})
            elif b['network'] == 'grpc':
                b['grpc-name'] = q.get('serviceName', [''])[0]
            return b

        elif p.scheme == "vmess":
            j = json.loads(base64.b64decode(uri[8:] + '=' * (-len(uri[8:]) % 4)).decode('utf-8', 'ignore'))
            b.update({
                'type': 'vmess',
                'name': j.get('ps'),
                'server': j.get('add'),
                'port': int(j.get('port')),
                'uuid': j.get('id'),
                'alterId': int(j.get('aid', 0)),
                'network': j.get('net', 'tcp'),
                'tls': j.get('tls') == 'tls',
                'sni': j.get('sni') or j.get('host')
            })
            if b['network'] == 'ws':
                b.update({'ws-path': j.get('path', '/'), 'ws-host': j.get('host', '')})
            elif b['network'] == 'grpc':
                b['grpc-name'] = j.get('path', '')
            return b

        elif p.scheme in ["trojan", "trojan-go"]:
            b.update({
                'type': 'trojan',
                'password': p.username,
                'sni': q.get('sni', [''])[0],
                'skip-cert-verify': q.get('allowInsecure', ['0'])[0] == '1',
                'udp': True
            })
            b['network'] = q.get('type', ['tcp'])[0]
            if b['network'] == 'ws':
                b.update({'ws-path': q.get('path', ['/'])[0], 'ws-host': q.get('host', [''])[0]})
            elif b['network'] == 'grpc':
                b['grpc-name'] = q.get('serviceName', [''])[0]
            if q.get('alpn'):
                b['alpn'] = q.get('alpn', [''])[0].split(',')
            return b

        elif p.scheme == "ss":
            try:
                raw = uri.replace("ss://", "").split("#")[0]
                plugin_info = {}
                if "?" in raw:
                    raw, query = raw.split("?", 1)
                    q_params = urllib.parse.parse_qs(query)
                    if 'plugin' in q_params:
                        plugin_str = urllib.parse.unquote(q_params['plugin'][0])
                        parts = plugin_str.split(';')
                        plugin_info['name'] = parts[0]
                        plugin_info['opts'] = {}
                        for opt in parts[1:]:
                            if "=" in opt:
                                k, v = opt.split("=", 1)
                                plugin_info['opts'][k] = v
                            else:
                                plugin_info['opts'][opt] = True

                def _split_host_port(hp: str):
                    hp = (hp or "").strip()
                    # IPv6 bracket form: [::1]:443
                    if hp.startswith('[') and ']' in hp:
                        host = hp[1:hp.find(']')]
                        rest = hp[hp.find(']')+1:]
                        if rest.startswith(':'):
                            return host, rest[1:]
                        return host, ""
                    # If it looks like IPv6 without brackets, assume last ':' splits port
                    if hp.count(':') > 1:
                        host, port = hp.rsplit(':', 1)
                        return host, port
                    # IPv4 / domain
                    if ':' in hp:
                        host, port = hp.split(':', 1)
                        return host, port
                    return hp, ""

                if "@" in raw:
                    user_part, host_part = raw.rsplit("@", 1)
                    host, port = _split_host_port(host_part)
                    try:
                        userinfo = safe_b64decode(user_part).decode()
                        method, password = userinfo.split(":", 1)
                    except:
                        method, password = user_part.split(":", 1)
                else:
                    decoded = safe_b64decode(raw).decode()
                    userinfo, hostport = decoded.rsplit("@", 1)
                    method, password = userinfo.split(":", 1)
                    host, port = _split_host_port(hostport)
                b.update({'type': 'ss', 'server': host, 'port': int(port), 'cipher': method, 'password': password})
                if plugin_info:
                    # Normalize shadow-tls plugin naming
                    if plugin_info.get('name') in ['shadowtls', 'shadow-tls']:
                        plugin_info['name'] = 'shadow-tls'
                    b['plugin'] = plugin_info['name']
                    b['plugin_opts'] = plugin_info['opts']
                return b
            except:
                pass


        elif p.scheme == "anytls":
            try:
                password = q.get('password', [''])[0] or (p.password or p.username or '')
                b.update({'type': 'anytls', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'password': password, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('alpn'): b['alpn'] = q.get('alpn', [''])[0]
                if q.get('idle-session-check-interval'): b['idle-session-check-interval'] = int(float(q.get('idle-session-check-interval', ['30'])[0]))
                if q.get('idle-session-timeout'): b['idle-session-timeout'] = int(float(q.get('idle-session-timeout', ['30'])[0]))
                if q.get('min-idle-session'): b['min-idle-session'] = int(float(q.get('min-idle-session', ['0'])[0]))
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                elif q.get('client-fingerprint'): b['fp'] = q.get('client-fingerprint', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass

        elif p.scheme in ["shadowtls", "stls"]:
            try:
                password = q.get('password', [''])[0] or (p.password or p.username or '')
                version = int(float(q.get('version', [q.get('v', ['1'])[0] if q.get('v') else '1'])[0]))
                b.update({'type': 'shadowtls', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'password': password, 'version': version, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('alpn'): b['alpn'] = q.get('alpn', [''])[0]
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                elif q.get('client-fingerprint'): b['fp'] = q.get('client-fingerprint', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass

        elif p.scheme.startswith("naive"):
            try:
                username = p.username or q.get('username', [''])[0]
                password = p.password or q.get('password', [''])[0]
                scheme = p.scheme.lower()
                use_quic = ('quic' in scheme)
                b.update({'type': 'naive', 'server': server, 'port': int(base_port or q.get('port', [443])[0] or 443), 'username': username, 'password': password, 'quic': use_quic, 'udp': True})
                if q.get('sni'): b['sni'] = q.get('sni', [''])[0]
                if q.get('fp'): b['fp'] = q.get('fp', ['chrome'])[0]
                is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('insecure', ['0'])[0] == '1'
                if is_insecure: b['skip-cert-verify'] = True
                return b
            except:
                pass
        elif p.scheme in ["hysteria2", "hy2"]:
            # Support both:
            # 1) Official multi-port style: hysteria2://auth@host:443,5000-6000?...#name
            # 2) Common extension: ?mport=5000-6000  (port hopping)
            netloc = p.netloc or ""
            userinfo = ""
            hostport = netloc
            if "@" in netloc:
                userinfo, hostport = netloc.rsplit("@", 1)

            # auth can be "password" or "user:password"
            userinfo = urllib.parse.unquote(userinfo)
            hy_pass = ""
            if ":" in userinfo:
                _u, _pw = userinfo.split(":", 1)
                hy_pass = urllib.parse.unquote(_pw or _u)
            else:
                hy_pass = userinfo

            host = ""
            port_part = ""

            if hostport.startswith('[') and ']' in hostport:
                # IPv6 form: [::1]:443,5000-6000
                host = hostport[1:hostport.find(']')]
                rest = hostport[hostport.find(']') + 1:]
                if rest.startswith(':'):
                    port_part = rest[1:]
            else:
                if ":" in hostport:
                    host, port_part = hostport.rsplit(":", 1)
                else:
                    host = hostport

            # port part (may contain comma/range)
            port_part = urllib.parse.unquote(port_part)
            port_parts = parse_ports_spec(port_part) if port_part else []
            # If port part is a single range "5000-6000", treat as ports too
            is_multi_in_port = (len(port_parts) > 1) or (len(port_parts) == 1 and "-" in port_parts[0])

            # mport extension (may contain ranges / list)
            mport_raw = (q.get('mport', [''])[0] or q.get('ports', [''])[0] or "").strip()
            mport_parts = parse_ports_spec(mport_raw)

            # Determine base port
            base_port = None
            if port_parts:
                m0 = re.match(r"^(\d+)", port_parts[0])
                if m0:
                    base_port = int(m0.group(1))
            if base_port is None:
                try:
                    base_port = p.port
                except:
                    pass

            if not base_port:
                return None

            # Build combined hopping ports spec (used for clash/sing-box)
            combined = []
            # If we already have multi-port in port-part, that usually already includes the base
            if port_parts:
                combined.extend(port_parts)
            else:
                combined.append(str(base_port))

            for pp in mport_parts:
                if pp and pp not in combined:
                    combined.append(pp)

            ports_spec = join_ports_spec(combined) if (len(combined) > 1 or (combined and "-" in combined[0])) else ""

            b = {
                "type": "hysteria2",
                "name": name,
                "server": host,
                "port": int(base_port),
                "password": hy_pass or (p.username or p.password or ""),
                "sni": q.get('sni', [''])[0],
                "alpn": q.get('alpn', ['h3'])[0],
            }

            if ports_spec:
                b["ports"] = ports_spec
                if mport_raw:
                    b["_mport"] = mport_raw
                    b["_ports_mode"] = "mport"
                else:
                    b["_ports_mode"] = "multi"

            if q.get('insecure', ['0'])[0] == '1' or q.get('allowInsecure', ['0'])[0] == '1' or q.get('allow_insecure', ['0'])[0] == '1':
                b['skip-cert-verify'] = True
            return b

        elif p.scheme == "tuic":
            # [v42.31 Fix] 强制 Unquote 用户信息，修复 %3A 导致的分割失败
            uuid = urllib.parse.unquote(p.username) if p.username else ""
            password = urllib.parse.unquote(p.password) if p.password else ""

            if not password and ":" in uuid:
                uuid, password = uuid.split(':', 1)

            b.update({
                'type': 'tuic',
                'uuid': uuid,
                'password': password,
                'sni': q.get('sni', [''])[0],
                'alpn': q.get('alpn', ['h3'])[0],
                'congestion_control': q.get('congestion_control', ['bbr'])[0]
            })

            # [v42.31 Fix] 兼容多种 insecure 写法
            is_insecure = q.get('allow_insecure', ['0'])[0] == '1' or \
                          q.get('allowInsecure', ['0'])[0] == '1' or \
                          q.get('insecure', ['0'])[0] == '1'
            if is_insecure:
                b['skip-cert-verify'] = True
            return b

    except:
        pass
    return None

def gen_clash(n, ip=None, port=None, name=None):
    try:
        if n['type'] == 'clash_import':
            c = copy.deepcopy(n['raw']); c['name'] = name; c['server'] = ip or c['server']; c['port'] = port or c['port']; return c
        c = {"name": name or n['name'], "type": n['type'], "server": ip or n['server'], "port": port or n['port'], "udp": True}
        if n['type'] in ['naive','shadowtls']: return None
        
        if n.get('skip-cert-verify'): c['skip-cert-verify'] = True
        
        server_str = str(c['server'])
        is_ip_server = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server_str)
        sni = n.get('sni') or n.get('servername')
        
        if is_ip_server and sni: c['skip-cert-verify'] = True
        elif sni and server_str != sni: c['skip-cert-verify'] = True

        def get_alpn_list(obj):
            val = obj.get('alpn', 'h3')
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
            val = str(val).strip()
            if not val:
                return ['h3']
            return [x.strip() for x in val.split(',')] if ',' in val else [val]

        if n['type'] == 'vless':
            c.update({"uuid":n['uuid'], "network":n['network'], "tls":n['tls']})
            if n.get('sni'): c['servername'] = n['sni']
            if n.get('flow'): c['flow'] = n['flow']
            if n.get('reality'): c.update({'reality-opts': {'public-key':n['pbk'], 'short-id':n['sid']}, 'client-fingerprint':n.get('fp','chrome')})
            else: c['client-fingerprint'] = 'chrome'
            if n.get('fp'): c['client-fingerprint'] = n['fp']
            if n['network']=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n['network']=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
        elif n['type'] == 'vmess':
            c.update({"uuid":n['uuid'], "alterId":n['alterId'], "cipher":"auto", "network":n['network']})
            if n.get('tls'): c['tls']=True; c['servername']=n.get('sni')
            else: c['tls']=False
            if n['network']=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n['network']=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
        elif n['type'] == 'trojan':
            c.update({"password":n['password'], "network":n.get('network','tcp')})
            if n.get('sni'): c['sni'] = n['sni']
            if n.get('alpn'): c['alpn'] = n['alpn'] 
            if n.get('network')=='ws': c['ws-opts'] = {'path':n.get('ws-path'), 'headers':{'Host':n.get('ws-host')}}
            elif n.get('network')=='grpc': c['grpc-opts'] = {'grpc-service-name':n.get('grpc-name')}
        elif n['type'] == 'hysteria2':
            c.update({"password": n.get('password',''), "sni": n.get('sni',''), "alpn": get_alpn_list(n)})
            # Port hopping (mihomo / clash.meta): set `ports` to enable port jumping; `port` will be ignored when `ports` exists.
            if n.get('ports'):
                parts = parse_ports_spec(n.get('ports'))
                # If caller overrides base port, rebuild spec with new base as first element
                if port and str(port) != str(n.get('port')):
                    orig_base = str(n.get('port'))
                    parts = [pp for pp in parts if pp != orig_base]
                    parts = [str(port)] + parts
                c['ports'] = join_ports_spec(parts)
        elif n['type'] == 'tuic':
            c.update({"uuid":n['uuid'], "password":n['password'], "sni":n.get('sni',''), 
                      "alpn": get_alpn_list(n)})
            if n.get('udp_relay_mode'): c['udp-relay-mode'] = n['udp_relay_mode']
            if sni and server_str != sni: c['skip-cert-verify'] = True
        elif n['type'] == 'anytls':
            c.update({
                'type': 'anytls',
                'password': n.get('password', ''),
                'udp': True,
                'client-fingerprint': n.get('fp', 'chrome'),
                'idle-session-check-interval': int(n.get('idle-session-check-interval', 30)),
                'idle-session-timeout': int(n.get('idle-session-timeout', 30)),
                'min-idle-session': int(n.get('min-idle-session', 0)),
                'sni': n.get('sni', '')
            })
            if n.get('alpn'): c['alpn'] = get_alpn_list(n)
            if n.get('skip-cert-verify'): c['skip-cert-verify'] = True
            
        elif n['type'] == 'ss':
            c.update({"cipher":n['cipher'], "password":n['password']})
            c['client-fingerprint'] = 'chrome'
            if n.get('plugin'):
                c['plugin'] = n['plugin']
                popts = n.get('plugin_opts', {})
                if n.get('plugin') == 'shadow-tls':
                    c['client-fingerprint'] = n.get('fp', 'chrome')
                    if 'version' in popts:
                        try: popts['version'] = int(popts['version'])
                        except: pass
                if n['plugin'] == 'v2ray-plugin':
                    c['plugin-opts'] = {'mode': popts.get('mode', 'websocket'), 'host': popts.get('host', ''), 'path': popts.get('path', '/'), 'tls': True if 'tls' in popts else False, 'skip-cert-verify': True if 'skip-cert-verify' in popts else False, 'mux': False, 'headers': {'Host': popts.get('host', ''), 'User-Agent': 'Mozilla/5.0'}}
                else: c['plugin-opts'] = popts
        return c
    except: return None

def gen_uri(n, ip=None, port=None, name=None):
    if not isinstance(n, dict) or 'type' not in n: return None
    server = ip or n['server']; port = str(port or n['port']); remark = urllib.parse.quote(name or n['name'])
    if n['type'] == 'vless':
        p = {'type':n['network'], 'security':'tls' if n['tls'] else 'none'}
        if n.get('reality'): p.update({'security':'reality', 'pbk':n['pbk'], 'sid':n['sid'], 'fp':n.get('fp','chrome')})
        elif n.get('sni'): p['sni'] = n['sni']
        if n.get('flow'): p['flow'] = n['flow']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('skip-cert-verify'): p['insecure'] = '1'; p['allowInsecure'] = '1'
        if n['network']=='ws': p.update({'path':n.get('ws-path','/'), 'host':n.get('ws-host','')})
        elif n['network']=='grpc': p['serviceName'] = n.get('grpc-name','')
        return f"vless://{n['uuid']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'vmess':
        j = {"v":"2", "ps":name or n['name'], "add":server, "port":port, "id":n['uuid'], "aid":n.get('alterId',0), "scy":"auto", "net":n['network'], "type":"none"}
        if n.get('tls'): j['tls']="tls"; j['host']=n.get('sni'); j['sni']=n.get('sni')
        else: j['tls']=""; j['host']=n.get('ws-host')
        if n['network']=='ws': j['path']=n.get('ws-path','/'); j['host']=n.get('ws-host','')
        elif n['network']=='grpc': j['path']=n.get('grpc-name','')
        return "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()
    elif n['type'] == 'trojan':
        p = {'type':n.get('network','tcp'), 'sni':n.get('sni',''), 'allowInsecure': '1' if n.get('skip-cert-verify') else '0'}
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('network')=='ws': p.update({'path':n.get('ws-path','/'), 'host':n.get('ws-host','')})
        elif n.get('network')=='grpc': p['serviceName'] = n.get('grpc-name','')
        return f"trojan://{n['password']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'hysteria2':
        p = {'sni': n.get('sni', ''), 'alpn': n.get('alpn', 'h3')}
        if n.get('skip-cert-verify'):
            p['insecure'] = '1'

        # Port hopping support:
        # - If original was ?mport=..., keep mport in query for compatibility.
        # - Otherwise, use official multi-port style in the port part: host:443,5000-6000
        ports_spec = n.get('ports', '')
        ports_mode = n.get('_ports_mode', '')

        if ports_spec:
            parts = parse_ports_spec(ports_spec)
            # If caller overrides base port, rebuild spec with new base as first element
            if port and str(port) != str(n.get('port')):
                orig_base = str(n.get('port'))
                parts = [pp for pp in parts if pp != orig_base]
                parts = [str(port)] + parts
            ports_spec = join_ports_spec(parts)

            if ports_mode == 'mport' and n.get('_mport'):
                p['mport'] = n.get('_mport')
                port_part = str(port)
            else:
                port_part = ports_spec
        else:
            port_part = str(port)

        return f"hysteria2://{n.get('password','')}@{server}:{port_part}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'tuic':
        p = {'sni':n.get('sni',''), 'congestion_control':n.get('congestion_control','bbr'), 'alpn': n.get('alpn', 'h3')}
        if n.get('skip-cert-verify'): p['allow_insecure']='1'
        return f"tuic://{n['uuid']}:{n['password']}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'anytls':
        p = {}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('idle-session-check-interval') is not None: p['idle-session-check-interval'] = str(n.get('idle-session-check-interval'))
        if n.get('idle-session-timeout') is not None: p['idle-session-timeout'] = str(n.get('idle-session-timeout'))
        if n.get('min-idle-session') is not None: p['min-idle-session'] = str(n.get('min-idle-session'))
        if n.get('skip-cert-verify'): p['insecure'] = '1'; p['allowInsecure'] = '1'
        return f"anytls://{urllib.parse.quote(n.get('password',''))}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'shadowtls':
        p = {'version': str(int(n.get('version', 1)))}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('alpn'): p['alpn'] = n['alpn']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('skip-cert-verify'): p['insecure'] = '1'
        return f"shadowtls://{urllib.parse.quote(n.get('password',''))}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'naive':
        p = {}
        if n.get('sni'): p['sni'] = n['sni']
        if n.get('fp'): p['fp'] = n['fp']
        if n.get('skip-cert-verify'): p['insecure'] = '1'
        scheme = 'naive+quic' if n.get('quic') else 'naive+https'
        user = urllib.parse.quote(n.get('username',''))
        pwd = urllib.parse.quote(n.get('password',''))
        return f"{scheme}://{user}:{pwd}@{server}:{port}?{urllib.parse.urlencode(p)}#{remark}"
    elif n['type'] == 'ss':
        auth = base64.b64encode(f"{n['cipher']}:{n['password']}".encode()).decode()
        uri = f"ss://{auth}@{server}:{port}"
        if n.get('plugin'):
            popts = n.get('plugin_opts', {})
            opt_str = ";".join([f"{k}={v}" if v is not True else k for k,v in popts.items()])
            plugin_str = urllib.parse.quote(f"{n['plugin']};{opt_str}")
            uri += f"/?plugin={plugin_str}"
        return f"{uri}#{remark}"
    return None

def gen_singbox(n, ip=None, port=None, name=None):
    try:
        server = ip or n['server']
        port = int(port or n['port'])
        tag = name or n['name']
        sb = {"type": n['type'], "tag": tag, "server": server, "server_port": port}
        
        def get_alpn_list(obj):
            val = obj.get('alpn', 'h3')
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
            val = str(val).strip()
            if not val:
                return ['h3']
            return [x.strip() for x in val.split(',')] if ',' in val else [val]

        if n['type'] == 'vless':
            sb.update({"uuid": n['uuid'], "flow": n.get('flow',''), "tls": { "enabled": n['tls'], "server_name": n.get('sni',''), "insecure": n.get('skip-cert-verify', False) }})
            
            is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(server))
            if is_ip and n.get('sni'): sb['tls']['insecure'] = True
            elif n.get('sni') and n['sni'] != server: sb['tls']['insecure'] = True

            if n.get('reality'): sb['tls'].update({"reality": {"enabled": True, "public_key": n.get('pbk'), "short_id": n.get('sid', '')}, "utls": {"enabled": True, "fingerprint": n.get('fp', 'chrome')}})
            if n['network'] == 'ws': sb["transport"] = {"type": "ws", "path": n.get('ws-path', '/'), "headers": {"Host": n.get('ws-host', '')}}
            elif n['network'] == 'grpc': sb["transport"] = {"type": "grpc", "service_name": n.get('grpc-name', '')}
        elif n['type'] == 'vmess':
            sb.update({"uuid": n['uuid'], "security": "auto", "alter_id": n.get('alterId', 0), "tls": { "enabled": n['tls'], "server_name": n.get('sni',''), "insecure": n.get('skip-cert-verify', False) }})
            if n['network'] == 'ws': sb["transport"] = {"type": "ws", "path": n.get('ws-path', '/'), "headers": {"Host": n.get('ws-host', '')}}
            elif n['network'] == 'grpc': sb["transport"] = {"type": "grpc", "service_name": n.get('grpc-name', '')}
        elif n['type'] == 'trojan':
            sb.update({"password": n['password'], "tls": { "enabled": True, "server_name": n.get('sni',''), "insecure": n.get('skip-cert-verify', False) }})
            if n.get('network') == 'ws': sb["transport"] = {"type": "ws", "path": n.get('ws-path', '/'), "headers": {"Host": n.get('ws-host', '')}}
            elif n.get('network') == 'grpc': sb["transport"] = {"type": "grpc", "service_name": n.get('grpc-name', '')}
        elif n['type'] == 'hysteria2':
            sb.update({"password": n.get('password', ''), "tls": { "enabled": True, "server_name": n.get('sni',''), "insecure": n.get('skip-cert-verify', False), "alpn": get_alpn_list(n) }})
            # Port hopping (sing-box >= 1.8): server_ports enables port hopping; server_port will be ignored when server_ports exists.
            if n.get('ports'):
                parts = parse_ports_spec(n.get('ports'))
                if parts:
                    parts = [pp.replace(':','-') for pp in parts]
                    # If caller overrides base port, rebuild spec with new base as first element
                    if port and str(port) != str(n.get('port')):
                        orig_base = str(n.get('port'))
                        parts = [pp for pp in parts if pp != orig_base]
                        parts = [str(port)] + parts
                    # sing-box uses list items like "443" / "5000-6000"
                    sb.pop('server_port', None)
                    sb['server_ports'] = parts
        elif n['type'] == 'tuic':
            sb.update({"uuid": n['uuid'], "password": n['password'], "congestion_control": n.get('congestion_control','bbr'), "tls": { "enabled": True, "server_name": n.get('sni',''), "insecure": n.get('skip-cert-verify', False), "alpn": get_alpn_list(n) }})
            if n.get('udp_relay_mode'): sb['udp_relay_mode'] = n['udp_relay_mode']
        elif n['type'] == 'ss':
            sb.update({"method": n['cipher'], "password": n['password']})
            if n.get('plugin'): return None  # sing-box outbounds don't support ss plugins
            if n.get('plugin') == 'v2ray-plugin':
                popts = n.get('plugin_opts', {})
                sb["plugin"] = "v2ray-plugin"
                sb["plugin_opts"] = f"mode={popts.get('mode','websocket')};host={popts.get('host','')};path={popts.get('path','/')};tls={popts.get('tls',False)}"
        return sb
    except: return None

async def async_process_subs():
    d = load_data(); subs = d.get('remote_subs', [])
    if not subs: return
    write_log("Sync Start (v42.31)")
    cfg = d.get('config', {}); all_nodes = []
    
    sem = asyncio.Semaphore(int(cfg.get('threads', 8))) 

    async def process_single_sub(session, sub_item):
        raw_text = sub_item.get('url', '')
        tag = sub_item.get('tag', '')
        enabled = sub_item.get('enabled', True)
        
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        
        http_links = []
        direct_nodes = []
        raw_content_parts = []

        for line in lines:
            if line.startswith('http'):
                http_links.append(line)
            elif any(line.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'anytls://', 'shadowtls://', 'stls://', 'naive+https://', 'naive+quic://', 'naive://']):
                node = parse_uri(line)
                if node: 
                    node['_tag'] = tag
                    node['_opt'] = enabled
                    direct_nodes.append(node)
            else:
                raw_content_parts.append(line)

        async def fetch_job(url):
            async with sem:
                return await fetch_single_url(session, url, int(cfg.get('timeout', 20)))
        
        if http_links:
            fetch_results = await asyncio.gather(*[fetch_job(u) for u in http_links])
            for _, info in fetch_results:
                if info: 
                    sub_item['info'] = info
                    break
            
            for text, _ in fetch_results:
                if text: raw_content_parts.append(text)

        if raw_content_parts:
            combined_content = "\n".join(raw_content_parts)
            decoded_nodes = decode_sub_content(combined_content)
            for n in decoded_nodes:
                n['_tag'] = tag
                n['_opt'] = enabled
                direct_nodes.append(n)
        
        return direct_nodes

    async with aiohttp.ClientSession(headers={'User-Agent': cfg.get('ua', 'v2rayNG/1.8.5')}) as session:
        tasks = [process_single_sub(session, sub) for sub in subs]
        results = await asyncio.gather(*tasks)
        
        for nodes in results:
            all_nodes.extend(nodes)
        
        unique = {}; valid_nodes = []
        for n in all_nodes:
            ports_fp = ''
            if n.get('ports'):
                ports_fp = str(n.get('ports'))
            elif n.get('server_ports'):
                ports_fp = ','.join([str(x) for x in n.get('server_ports')])
            fp = f"{n.get('type')}|{n.get('uuid','')}|{n.get('server')}|{n.get('port')}|{ports_fp}"
            if fp not in unique: unique[fp] = n
        
        for n in unique.values():
            n['_clean_name'] = await smart_identify_region(n, n.get('_tag', ''))
            valid_nodes.append(n)
            
        d['cached_nodes'] = valid_nodes; d['remote_subs'] = subs; d['last_sync'] = int(time.time())
        save_data(d); save_cache(); write_log(f"Sync End. Total: {len(valid_nodes)}")

def run_sync_thread(): 
    try: asyncio.run(async_process_subs())
    except Exception as e: write_log(f"Sync Error: {e}")

def update_ips_with_separator(current_text, new_ips_list):
    manual_part = current_text.split(IP_SEPARATOR)[0].strip() if IP_SEPARATOR in current_text else current_text.strip()
    return f"{manual_part}\n\n{IP_SEPARATOR}\n" + "\n".join(new_ips_list)

def auto_sync_task():
    global IS_SYNCING
    write_log("Scheduler Started (v42.31)")
    while True:
        try:
            time.sleep(5)
            if IS_SYNCING: continue
            d = load_data(); interval = int(d.get('config', {}).get('interval', 14400))
            if interval > 0 and time.time() - d.get('last_sync', 0) > interval:
                IS_SYNCING = True; write_log("Auto Sync Triggered...")
                if d.get('cf_api_url') and requests:
                    try:
                        api = d.get('cf_api_url')
                        fetch_url = api
                        if not api.startswith('http'): 
                             fetch_url = f"https://{api}/sub?host=speed.cloudflare.com&uuid=00000000-0000-0000-0000-000000000000"
                        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                        r = requests.get(fetch_url, timeout=20, verify=False, headers=headers)
                        if r.status_code == 200:
                            content = r.text
                            fetched_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', content)
                            if not fetched_ips:
                                try:
                                    pad = len(content) % 4
                                    if pad: content += '=' * (4 - pad)
                                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                                    fetched_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', decoded)
                                except: pass
                            if fetched_ips:
                                d['ips'] = update_ips_with_separator(d.get('ips', ''), list(set(fetched_ips)))
                                save_data(d)
                                write_log(f"Auto IP Updated: {len(fetched_ips)} IPs")
                    except Exception as e: write_log(f"Auto IP Error: {e}")
                asyncio.run(async_process_subs()); IS_SYNCING = False
        except Exception as e:
            write_log(f"Scheduler Critical Error: {e}")
            time.sleep(60)
threading.Thread(target=auto_sync_task, daemon=True).start()

@app.route('/')
def root(): return redirect(f'/{LOGIN_PATH}')

@app.route(f'/{LOGIN_PATH}', methods=['GET', 'POST'])
def admin_entry():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            resp = make_response(redirect(f'/{LOGIN_PATH}'))
            resp.set_cookie('auth', WEB_PASSWORD, max_age=86400*30)
            return resp
        return render_template('index.html', authorized=False)
    if request.cookies.get('auth') == WEB_PASSWORD:
        d = load_data()
        logs = ""
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f: logs = "".join(deque(f, maxlen=50))
        token = d.get('config', {}).get('sub_token', WEB_PASSWORD)
        return render_template('index.html', authorized=True, data=d, node_count=len(d.get('cached_nodes',[])), logs=logs, sub_url=f"{request.url_root}sub?token={token}")
    return render_template('index.html', authorized=False)

@app.route('/login', methods=['POST'])
def login_compat(): return redirect(f'/{LOGIN_PATH}')

@app.route('/api/status', methods=['GET'])
def api_status():
    d = load_data()
    ip_list = [x for x in d['ips'].splitlines() if x.strip()]
    interval = int(d.get('config', {}).get('interval', 14400))
    last = d.get('last_sync', 0)
    ttl = 0
    if interval > 0: ttl = max(0, int((last + interval) - time.time()))
    return jsonify({"app_version": APP_VERSION, "last_sync": last, "ip_count": len(ip_list), "is_syncing": IS_SYNCING, "ttl": ttl})

@app.route('/save', methods=['POST'])
def save():
    d = load_data()
    d['ips'] = request.form.get('ips'); d['cf_api_url'] = request.form.get('cf_api_url')
    d['max_ips_per_node'] = int(request.form.get('max_ips_per_node', 0))
    d['clash_tpl'] = request.form.get('clash_tpl')
    d['config']['interval'] = int(request.form.get('cfg_interval', 14400))
    d['config']['threads'] = int(request.form.get('cfg_threads', 50))
    d['config']['timeout'] = int(request.form.get('cfg_timeout', 15))
    d['config']['ua'] = request.form.get('cfg_ua')
    d['config']['sub_token'] = request.form.get('cfg_sub_token')
    d['config']['custom_groups'] = request.form.get('cfg_custom_groups', '').replace('，', ',')
    urls = request.form.getlist('sub_urls[]')
    tags = request.form.getlist('sub_tags[]')
    enables = request.form.getlist('sub_enables[]')
    new_subs = []
    for i, u in enumerate(urls):
        if u.strip():
            old_info = d['remote_subs'][i].get('info') if i < len(d['remote_subs']) else None
            is_enabled = (enables[i] == '1') if i < len(enables) else True
            new_subs.append({"url": u.strip(), "tag": tags[i].strip(), "enabled": is_enabled, "info": old_info})
    d['remote_subs'] = new_subs
    save_data(d)
    threading.Thread(target=run_sync_thread).start()
    return redirect(f'/{LOGIN_PATH}?status=saved')

@app.route('/api/fetch_ips', methods=['POST'])
def api_fetch_ips():
    try:
        if not requests: return jsonify({"status":"error", "msg":"requests missing"})
        user_input = request.json.get('url', '').strip()
        if not user_input: return jsonify({"status":"error", "msg":"输入为空"})
        target_url = user_input
        if not user_input.startswith('http'): target_url = f"https://{user_input}/sub?host=speed.cloudflare.com&uuid=00000000-0000-0000-0000-000000000000"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        r = requests.get(target_url, timeout=15, verify=False, headers=headers)
        if r.status_code != 200: return jsonify({"status":"error", "msg":f"下载失败 (HTTP {r.status_code})"})
        content = r.text
        if not content: return jsonify({"status":"error", "msg":"返回内容为空"})
        fetched_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', content)
        if not fetched_ips:
            try:
                pad = len(content) % 4
                if pad: content += '=' * (4 - pad)
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
                fetched_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', content)
            except: pass
        if not fetched_ips: return jsonify({"status":"error", "msg":"未在返回内容中找到IP (格式不匹配)"})
        d = load_data()
        d['ips'] = update_ips_with_separator(d.get('ips', ''), list(set(fetched_ips)))
        d['cf_api_url'] = user_input
        save_data(d)
        return jsonify({"status":"success", "ips": d['ips']})
    except Exception as e: return jsonify({"status":"error", "msg":str(e)})

@app.route('/api/sync_subs', methods=['POST'])
def api_sync_subs():
    threading.Thread(target=run_sync_thread).start(); return jsonify({"msg": "Started"})

@app.route('/api/logs', methods=['GET'])
def api_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f: return "".join(deque(f, maxlen=50))
    return ""

@app.route('/api/nodes', methods=['GET'])
def api_nodes(): return jsonify(load_data().get('cached_nodes', []))

@app.route('/api/node_delete', methods=['POST'])
def api_node_delete():
    idx = request.json.get('index')
    d = load_data()
    if 0 <= idx < len(d['cached_nodes']):
        del d['cached_nodes'][idx]
        save_data(d)
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"})

@app.route('/api/snapshot_dl')
def snapshot_dl():
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(DATA_FILE): zf.write(DATA_FILE, 'data.json')
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"backup_{int(time.time())}.zip")

@app.route('/api/snapshot_restore', methods=['POST'])
def snapshot_restore():
    f = request.files['file']
    if f:
        with zipfile.ZipFile(f) as zf: zf.extractall(DATA_DIR)
        return "OK"
    return "Error"

@app.route('/sub')
def sub():
    d = load_data()
    token = request.args.get('token')
    correct_token = d.get('config', {}).get('sub_token') or WEB_PASSWORD
    if SUB_TOKEN_CHECK and token != correct_token: return "Access Denied", 403
    
    nodes = d.get('cached_nodes', [])
    raw_ips = d['ips'].splitlines()
    ips = [x.strip() for x in raw_ips if x.strip() and IP_SEPARATOR not in x and "#####" not in x]
    
    flag = request.args.get('flag', '')
    raw_mode = request.args.get('raw') == '1'
    
    filter_kw = request.args.get('filter', '')
    exclude_kw = request.args.get('exclude', '')
    
    final_list = []
    pool = ips
    if d.get('max_ips_per_node', 0) > 0 and len(ips) > d.get('max_ips_per_node'):
        pool = random.sample(ips, d.get('max_ips_per_node'))

    tag_counters = {}

    for n in nodes:
        if not isinstance(n, dict) or 'type' not in n: continue
        name = n['name']
        
        tag = n.get('_tag', '')
        clean_name = n.get('_clean_name', '')
        search_target = f"{name} {tag} {clean_name}"
        
        if filter_kw and not re.search(re.escape(filter_kw), search_target, re.IGNORECASE): continue
        if exclude_kw and re.search(re.escape(exclude_kw), search_target, re.IGNORECASE): continue
        
        if tag not in tag_counters: tag_counters[tag] = 1
        
        node_name_base = clean_name if clean_name else name
        if tag and tag not in node_name_base: node_name_base = f"{node_name_base} {tag}"
        node_name_base = f"{node_name_base} {str(tag_counters[tag]).zfill(2)}"
        
        target_ips = [None]
        if not raw_mode:
            is_opt_enable = n.get('_opt', True)
            is_protocol_support = n['type'] in ['vless', 'vmess', 'trojan'] and n.get('network') in ['ws', 'grpc']
            if n.get('reality'): is_protocol_support = False
            
            if is_opt_enable and is_protocol_support and ips:
                target_ips = pool
        
        for i, ip_str in enumerate(target_ips):
            ip = None; port = None
            if ip_str:
                if ":" in ip_str: ip, port = ip_str.split(":")
                else: 
                    ip = ip_str
                    is_secure = n.get('tls') or n.get('reality') or n['type'] in ['trojan', 'hysteria2', 'tuic']
                    if n['type'] == 'ss' and n.get('plugin_opts', {}).get('tls'): is_secure = True
                    port = 443 if is_secure else 80
                port = int(port)
            
            node_name = node_name_base
            if not raw_mode and len(target_ips) > 1: node_name = f"{node_name_base}-{i+1}"
            
            obj = None
            if flag == 'clash': obj = gen_clash(n, ip, port, node_name)
            elif flag == 'singbox': obj = gen_singbox(n, ip, port, node_name)
            else: obj = gen_uri(n, ip, port, node_name)
            if obj: final_list.append(obj)
            if len(final_list) >= MAX_NODES_OUTPUT: break
        tag_counters[tag] += 1
        if len(final_list) >= MAX_NODES_OUTPUT: break

    filename = "subs"
    if filter_kw: filename += f"_{filter_kw}"
    filename = urllib.parse.quote(filename)
    
    headers = {}
    if flag == 'clash':
        if not yaml: return "PyYAML missing", 500
        y_str = yaml.dump(final_list, allow_unicode=True, sort_keys=False)
        tpl = d.get('clash_tpl', 'proxies:\n#PLACEHOLDER#')
        if "#PLACEHOLDER#" not in tpl: tpl += "\nproxies:\n#PLACEHOLDER#"
        y_str_indented = "\n".join(["  " + l for l in y_str.splitlines()])
        names = "\n".join([f"      - {n['name']}" for n in final_list])
        resp_data = tpl.replace("#PLACEHOLDER#", y_str_indented).replace("#PLACEHOLDER_NAMES#", names)
        headers = {'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': f'inline; filename={filename}.yaml'}
    elif flag == 'singbox':
        resp_data = json.dumps(final_list, indent=2, ensure_ascii=False)
        headers = {'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': f'inline; filename={filename}.json'}
    else:
        resp_data = base64.b64encode("\n".join(final_list).encode()).decode()
        headers = {'Content-Type': 'text/plain', 'Content-Disposition': f'inline; filename={filename}.txt'}
    
    return Response(resp_data, headers=headers)

if __name__ == '__main__':
    if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
