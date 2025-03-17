# WordPress Username Enumeration and Password Brute Force Tool

A powerful Python-based tool for WordPress security testing. This tool efficiently enumerates WordPress usernames and performs targeted password brute force attacks using common password patterns.

Created by Chirag Artani from [3rag.com](https://3rag.com)

## Features

- **Username Enumeration**: Discovers WordPress usernames through multiple methods:
  - Author page enumeration (`/?author=X`)
  - WordPress REST API (`/wp-json/wp/v2/users`)

- **Intelligent Password Testing**: Tests discovered usernames against:
  - The username itself as password
  - Username with common suffixes (123, admin123, etc.)
  - Common default passwords

- **Performance Optimized**:
  - Multi-threading for concurrent password attempts
  - Site-level parallelism for testing multiple WordPress installations
  - Smart cancellation of remaining password attempts once credentials are found

- **Stealth Features**:
  - Rotating user agents to avoid detection
  - Configurable delays between requests
  - Session management for efficient requests

- **User-Friendly Output**:
  - Real-time status updates with timestamps
  - Color-coded output for easy reading
  - Immediate recording of successful logins
  - Comprehensive summary reports

## Installation

```bash
# Clone the repository
git clone https://github.com/chiragartani/wp-enum-brute.git
cd wp-enum-brute

# Install required dependencies
pip install requests colorama
```

## Usage

### Basic Usage

```bash
# Scan a single WordPress site
python wp_enum_brute.py -t example.com

# Scan multiple sites from a file
python wp_enum_brute.py -l targets.txt
```

### Command Line Arguments

```
-t, --target       Target URL (e.g., http://example.com)
-l, --url-list     File containing list of target URLs (one per line)
-o, --output       Output file for successful logins (default: wp_successful_logins.txt)
-w, --workers      Number of concurrent password attempts per target (default: 10)
-s, --site-workers Number of concurrent sites to scan (default: 5)
-v, --verbose      Enable verbose output (shows failed attempts)
--timeout          Request timeout in seconds (default: 10)
--only-enumerate   Only enumerate usernames, skip password brute force
--delay            Delay between requests in seconds (default: 0)
```

### Examples

```bash
# Only enumerate usernames without brute forcing passwords
python wp_enum_brute.py -t example.com --only-enumerate

# Scan with higher concurrency (20 password attempts, 10 sites at once)
python wp_enum_brute.py -l targets.txt -w 20 -s 10

# Add delay between requests to avoid detection (500ms)
python wp_enum_brute.py -l targets.txt --delay 0.5

# Save results to a specific file
python wp_enum_brute.py -t example.com -o results/wordpress_logins.txt

# Show all login attempts (verbose mode)
python wp_enum_brute.py -t example.com -v
```

## Output Example

```
[10:15:23] [INFO] Enumerating usernames from http://example.com
[10:15:24] [SUCCESS] Found username via redirect: admin on http://example.com
[10:15:25] [SUCCESS] Found username in body: editor on http://example.com
[10:15:26] [INFO] Found 2 unique username(s) on http://example.com: admin, editor
[10:15:26] [INFO] Starting brute force against 2 username(s) on http://example.com with 10 workers
[10:15:26] [INFO] Queuing 15 passwords for username 'admin' on http://example.com
[10:15:26] [INFO] Queuing 15 passwords for username 'editor' on http://example.com
[10:15:28] [SUCCESS] ✓ SUCCESS: http://example.com - admin:admin123
[10:15:33] [INFO] Brute force completed on http://example.com. 17 attempts. 1 successful logins.

==================================================
[10:15:33] [SUCCESS] SUMMARY - Successful logins for http://example.com:
  ✓ http://example.com - admin:admin123
[10:15:33] [INFO] Results saved to wp_successful_logins.txt
==================================================
```

## Ethical Usage

This tool is intended for legitimate security testing with proper authorization. Unauthorized testing against websites you don't own is illegal and unethical. Always:

- Get written permission before testing
- Use responsibly and ethically
- Follow responsible disclosure practices

## Disclaimer

This tool is provided for educational and authorized penetration testing purposes only. The author is not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
