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
# GO 核心代码区 (极致性能版)
# ==========================================

# 1. 协议验证器 (只做握手，用于快速筛选端口)
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
			// 发送 SOCKS5 握手
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			conn.Close()
			// 只要握手成功 (无论是否需要认证)，都认为是 Socks5 端口
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

# 2. 多模式扫描器 (Public/Private/Both)
# 原生 Go 实现所有逻辑，无 Python 延迟
GO_SOURCE_CODE_SCANNER = r'''
package main
import ("flag";"fmt";"net";"os";"strings";"sync";"sync/atomic";"time")

// ScanMode: 0=Both, 1=PublicOnly, 2=PrivateOnly
var scanMode int

type Job struct { Host string; Port string; User string; Pass string }

func worker(jobs <-chan Job, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for j := range jobs {
		target := net.JoinHostPort(j.Host, j.Port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			// 发送支持 NoAuth(0x00) 和 UserPass(0x02) 的请求
			conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			reply := make([]byte, 2)
			n, _ := conn.Read(reply)
			
			if n > 1 && reply[0] == 0x05 {
				authMethod := reply[1]
				
				// 逻辑分支：根据模式和服务器响应决定是否输出
				
				// 情况 A: 服务器无需认证 (OPEN)
				if authMethod == 0x00 {
					if scanMode == 0 || scanMode == 1 { // Both 或 Public
						fmt.Printf("S|%s|%s||OPEN\n", j.Host, j.Port)
					}
				} else if authMethod == 0x02 {
					// 情况 B: 服务器需要认证
					if (scanMode == 0 || scanMode == 2) && j.User != "" { // Both 或 Private，且有字典
						// 发送认证包
						authReq := []byte{0x01}
						authReq = append(authReq, byte(len(j.User))); authReq = append(authReq, j.User...)
						authReq = append(authReq, byte(len(j.Pass))); authReq = append(authReq, j.Pass...)
						conn.Write(authReq)
						
						authResp := make([]byte, 2)
						n2, _ := conn.Read(authResp)
						
						if n2 > 1 && authResp[0] == 0x01 && authResp[1] == 0x00 {
							fmt.Printf("S|%s|%s|%s|%s\n", j.Host, j.Port, j.User, j.Pass)
						}
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
	proxyFile := flag.String("proxyFile", "", "Proxy List")
	dictFile := flag.String("dictFile", "", "Dict File (Optional for Public)")
	mode := flag.Int("mode", 0, "0=Both, 1=Public, 2=Private")
	threads := flag.Int("threads", 1000, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()
	
	scanMode = *mode

	// 读取代理
	pData, _ := os.ReadFile(*proxyFile)
	pLines := strings.Split(string(pData), "\n")
	var proxies []string
	for _, l := range pLines { if t := strings.TrimSpace(l); t != "" { proxies = append(proxies, t) } }

	// 读取字典 (如果模式是 PublicOnly，字典可以是空的或者不存在)
	var dLines []string
	if *mode != 1 { // 如果不是仅跑公共，则需要字典
		dData, _ := os.ReadFile(*dictFile)
		dLines = strings.Split(string(dData), "\n")
		var cleanDLines []string
		for _, l := range dLines { if t := strings.TrimSpace(l); t != "" { cleanDLines = append(cleanDLines, t) } }
		dLines = cleanDLines
	}

	jobs := make(chan Job, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ { wg.Add(1); go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count) }

	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			
			// 核心任务分配逻辑
			if *mode == 1 {
				// Public Only: 只需要跑一次 IP，不需要跑字典
				jobs <- Job{Host: parts[0], Port: parts[1], User: "", Pass: ""}
			} else {
				// Private or Both: 需要跑字典
				if len(dLines) > 0 {
					for _, cred := range dLines {
						cParts := strings.SplitN(cred, ":", 2)
						if len(cParts) == 2 {
							jobs <- Job{Host: parts[0], Port: parts[1], User: cParts[0], Pass: cParts[1]}
						}
					}
				} else if *mode == 0 {
				    // 如果是 Both 模式但没字典，至少要检测 Open
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
# GeoIP 管理模块
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

    print("正在检查核心组件...")
    for name, code in sources.items():
        out_path = os.path.join(CACHE_DIR, name + (".exe" if sys.platform=="win32" else ""))
        hash_path = os.path.join(CACHE_DIR, name + ".hash")
        cur_hash = hashlib.sha256(code.encode()).hexdigest()
        if not (os.path.exists(out_path) and os.path.exists(hash_path) and open(hash_path).read() == cur_hash):
            print(f"  - 编译 {name}...")
            src_path = os.path.join(CACHE_DIR, name + ".go")
            with open(src_path, "w", encoding="utf-8") as f: f.write(code)
            subprocess.run([go_exec, "build", "-ldflags", "-s -w", "-o", out_path, src_path], capture_output=True, env=build_env)
            with open(hash_path, 'w') as f: f.write(cur_hash)
        COMPILED_BINARIES[name] = out_path
    return True

def run_go_process(bin_name, args, total_tasks, raw_output_file):
    bin_path = COMPILED_BINARIES.get(bin_name)
    if not bin_path: return
    print(f"\n启动引擎 | 任务量: {total_tasks}")
    try:
        proc = subprocess.Popen([bin_path] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', bufsize=1)
        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, mininterval=0.5) as pbar, open(raw_output_file, 'w', encoding='utf-8') as f:
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None: break
                if not line: continue
                line = line.strip()
                if line == "P": pbar.update(50)
                elif line.startswith("S|"):
                    f.write(line + "\n"); f.flush()
                    tqdm.write(f"  [+] 命中: {line.split('|')[1]}")
    except Exception as e: print(f"错误: {e}")

# ==========================================
# 业务逻辑：功能分离
# ==========================================

# --- 模块 1: 协议探测 ---
def execute_protocol_detection(output_dir, geoip_mgr):
    print("\n[协议探测模式] - 筛选开放 Socks5 端口")
    f_path = input("输入 IP:Port 列表文件: ").strip().strip('"')
    if not os.path.exists(f_path):
        print("文件不存在")
        return

    threads = input("并发线程 (默认1000): ") or "1000"
    raw_out = os.path.join(output_dir, "raw_protocol.txt")
    total = sum(1 for x in open(f_path, errors='ignore'))
    
    run_go_process("protocol_verifier", ["-inputFile", f_path, "-threads", threads], total, raw_out)
    
    # 结果处理
    valid_ips = []
    if os.path.exists(raw_out):
        with open(raw_out, 'r') as f:
            for line in f:
                if line.startswith("S|"): valid_ips.append(line.strip().split("|")[1])
    
    if not valid_ips:
        print("[-] 未探测到有效结果。")
        return
        
    print(f"\n[+] 探测到 {len(valid_ips)} 个有效地址。")
    
    # 保存
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    fname = f"Protocol_Valid_{timestamp}.txt"
    fpath = os.path.join(output_dir, fname)
    
    print("是否附加 GeoIP? (y/n)")
    use_geo = input().lower() == 'y'
    
    with open(fpath, 'w', encoding='utf-8') as f:
        for ip in valid_ips:
            if use_geo:
                info = geoip_mgr.lookup(ip.split(":")[0])
                f.write(f"{ip} #{info}\n")
            else:
                f.write(f"{ip}\n")
                
    print(f"[完成] 结果已保存至: {fname}")
    print(f"提示: 你可以使用该文件作为 [2. 扫描代理] 的输入。")


# --- 模块 2: 扫描代理 ---
def execute_proxy_scanning(output_dir, geoip_mgr):
    print("\n[扫描代理模式] - 检测 Public/Private 代理")
    f_path = input("输入 IP:Port 列表文件 (支持直接导入): ").strip().strip('"')
    if not os.path.exists(f_path):
        print("文件不存在")
        return

    print("\n请选择扫描模式:")
    print("  [1] Public Only (只扫免密开放代理，速度极快)")
    print("  [2] Private Only (只扫密码认证代理)")
    print("  [3] Both (同时扫描，自动分类)")
    c = input("选择: ")
    
    mode = 0
    dict_file = ""
    tdir = tempfile.mkdtemp()
    
    try:
        if c == '1':
            mode = 1
            # 制造空字典
            dict_file = os.path.join(tdir, "empty.txt")
            open(dict_file,'w').close()
            
        elif c in ['2', '3']:
            mode = 2 if c=='2' else 0
            print("\n[配置字典]")
            print("  [1] User + Pass 组合")
            print("  [2] User = Pass 同名")
            print("  [3] User:Pass 单文件")
            dc = input("选择: ")
            
            d_out = os.path.join(tdir, "d.txt")
            if dc == '1':
                u = open(input("User File: ").strip('"')).read().splitlines()
                p = open(input("Pass File: ").strip('"')).read().splitlines()
                with open(d_out,'w') as f:
                    for x in u:
                        for y in p: f.write(f"{x.strip()}:{y.strip()}\n")
            elif dc == '2':
                w = open(input("Wordlist: ").strip('"')).read().splitlines()
                with open(d_out,'w') as f:
                    for x in w: f.write(f"{x.strip()}:{x.strip()}\n")
            elif dc == '3':
                shutil.copy(input("User:Pass File: ").strip('"'), d_out)
            else: return
            dict_file = d_out
        else: return
        
        threads = input("并发线程 (默认1000): ") or "1000"
        raw_out = os.path.join(tdir, "raw_scan.txt")
        
        # 任务估算
        pc = sum(1 for x in open(f_path, errors='ignore'))
        dc = 1
        if mode != 1: dc = sum(1 for x in open(dict_file))
        if dc == 0: dc = 1
        total = pc if mode == 1 else pc * dc
        
        # 运行
        run_go_process("scanner", 
                      ["-proxyFile", f_path, "-dictFile", dict_file, "-mode", str(mode), "-threads", threads],
                      total, raw_out)
        
        # 结果分类保存
        public_set = set()
        private_set = set()
        
        if os.path.exists(raw_out):
            with open(raw_out, 'r') as f:
                for line in f:
                    if not line.startswith("S|"): continue
                    p = line.strip().split("|")
                    if len(p) >= 5:
                        if p[4] == "OPEN":
                            public_set.add(f"socks5://{p[1]}:{p[2]}")
                        else:
                            private_set.add(f"socks5://{p[3]}:{p[4]}@{p[1]}:{p[2]}")
        
        timestamp = datetime.now().strftime("%Y%m%d-%H%M")
        print("\n是否附加 GeoIP? (y/n)")
        use_geo = input().lower() == 'y'
        
        def save(data, prefix):
            if not data: return
            fn = f"{prefix}_{timestamp}.txt"
            fp = os.path.join(output_dir, fn)
            with open(fp, 'w') as f:
                for item in sorted(list(data)):
                    if use_geo:
                        ip = item.split("@")[1].split(":")[0] if "@" in item else item.split("//")[1].split(":")[0]
                        info = geoip_mgr.lookup(ip)
                        f.write(f"{item} #{info}\n")
                    else:
                        f.write(f"{item}\n")
            print(f"[保存] {prefix}: {len(data)} 条 -> {fn}")
            
        if public_set: save(public_set, "Public_Proxies")
        if private_set: save(private_set, "Private_Proxies")
        if not public_set and not private_set: print("[-] 未扫描到有效结果")
            
    finally:
        shutil.rmtree(tdir)

# --- 主入口 ---
def main():
    if not compile_go_binaries(): sys.exit(1)
    geoip = GeoIPManager()
    geoip.ensure_databases()
    
    out_dir = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "="*50)
    print(" Socks5 Toolkit (Decoupled Mode)")
    print("="*50)

    try:
        while True:
            print("\n--- 功能菜单 ---")
            print("  [1] 协议探测 (只筛选 Socks5 端口)")
            print("  [2] 扫描代理 (检测 Public/Private 可用性)")
            print("  [q] 退出")
            
            c = input("\n请选择: ").lower()
            
            if c == '1':
                execute_protocol_detection(out_dir, geoip)
            elif c == '2':
                execute_proxy_scanning(out_dir, geoip)
            elif c == 'q':
                break
            else:
                print("无效输入")
                    
    finally:
        geoip.close()

if __name__ == "__main__": main()
