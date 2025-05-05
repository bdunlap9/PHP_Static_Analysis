#!/usr/bin/env python3

import os, re, json, argparse, logging
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------------------------------------------------
# Configuration: vulnerability patterns & sanitizers
# -------------------------------------------------------------------
RAW_VULN_PATTERNS = [
    {"name": "Use of eval()", "severity": 3, "message": "Eval on user input", "impact": "Arbitrary code execution", "recommendation": "Remove eval() usage", "regex": r"\beval\s*\("},
    {"name": "Obfuscated eval(b64)", "severity": 3, "message": "eval(base64_decode())", "impact": "RCE via encoded payload", "recommendation": "Disable obfuscation", "regex": r"eval\s*\(\s*base64_decode"},
    {"name": "Shell execution", "severity": 3, "message": "system/exec functions", "impact": "Command injection", "recommendation": "Sanitize inputs; avoid shell calls", "regex": r"\b(system|exec|shell_exec|passthru)\s*\("},
    {"name": "SSRF via curl_init()", "severity": 3, "message": "curl_init() on user input", "impact": "Internal resource access", "recommendation": "Allowlist URLs", "regex": r"curl_init\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Unsafe readfile()", "severity": 3, "message": "readfile() on user input", "impact": "File disclosure", "recommendation": "Validate file paths", "regex": r"\breadfile\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "SQL Injection", "severity": 3, "message": "SQL queries built from unescaped superglobals", "impact": "DB compromise", "recommendation": "Use prepared statements", "regex": r"\b(mysql_query|mysqli_query|PDO->query|PDO->exec)\s*\(.*\$_(GET|POST|REQUEST)"},
    {"name": "Reflected XSS", "severity": 2, "message": "Echo of user input into HTML", "impact": "Arbitrary JS execution", "recommendation": "Escape output via htmlspecialchars()", "regex": r"echo\s+\$_(GET|POST|REQUEST)\s*;"},
    {"name": "Include/Require user input", "severity": 3, "message": "Dynamic include of user file", "impact": "LFI/RFI code execution", "recommendation": "Validate include paths", "regex": r"\b(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "File read from user input", "severity": 3, "message": "file_get_contents() on unsanitized input", "impact": "Arbitrary file read", "recommendation": "Sanitize & allowlist paths", "regex": r"\bfile_get_contents\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Unvalidated file write", "severity": 3, "message": "file_put_contents() on user path", "impact": "File overwrite/webshell upload", "recommendation": "Restrict write dirs & filenames", "regex": r"\bfile_put_contents\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Unsafe fopen for writing", "severity": 3, "message": "fopen() write mode on user path", "impact": "File overwrite", "recommendation": "Disallow fopen write on user paths", "regex": r"fopen\s*\(\s*\$_(GET|POST|REQUEST)\s*,\s*[\"']w"},
    {"name": "Directory traversal", "severity": 2, "message": "Potential directory traversal via ../", "impact": "Restricted file access", "recommendation": "Normalize & block ../ sequences", "regex": r"\.\./"},
    {"name": "Open redirect", "severity": 2, "message": "Location header with user input", "impact": "Phishing redirect", "recommendation": "Validate redirect URLs", "regex": r"header\s*\(\s*[\"']Location:.*\$_(GET|POST|REQUEST)"},
    {"name": "Use of weak hash", "severity": 2, "message": "MD5 or SHA1 is not secure", "impact": "Collision attacks", "recommendation": "Use bcrypt or Argon2", "regex": r"\b(md5|sha1)\s*\("},
    {"name": "Insecure randomness", "severity": 2, "message": "rand()/mt_rand() is predictable", "impact": "Predictable tokens", "recommendation": "Use random_int()", "regex": r"\b(mt_rand|rand)\s*\("},
    {"name": "Insecure file()", "severity": 3, "message": "file() on user input", "impact": "Arbitrary file disclosure (and possible RFI/LFI)", "recommendation": "Validate & allowlist file paths", "regex": r"\bfile\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Dynamic class instantiation", "severity": 3, "message": "new $_GET['class'] or similar", "impact": "PHP object injection / code execution", "recommendation": "Only instantiate from a fixed whitelist", "regex": r"\bnew\s*\$_\s*\[\s*(?:'\"?)(GET|POST|REQUEST)(?:'\"?)\s*\]"},
    {"name": "Unvalidated setcookie()", "severity": 2, "message": "setcookie() with user-supplied value", "impact": "Cookie spoofing / session hijack", "recommendation": "Sanitize values and set HttpOnly/Secure flags", "regex": r"\bsetcookie\s*\(.*\$_(GET|POST|REQUEST)"},
    {"name": "Use of mcrypt_*", "severity": 2, "message": "Deprecated mcrypt functions", "impact": "Broken encryption", "recommendation": "Migrate to openssl or sodium", "regex": r"\bmcrypt_[a-zA-Z_]+\s*\("},
    {"name": "Insecure SSL context", "severity": 2, "message": "SSL peer verification disabled", "impact": "MITM attacks", "recommendation": "Always verify SSL certificates", "regex": r"stream_context_create\s*\(\s*\[.*(?:verify_peer|verify_peer_name)\s*=>\s*false"},
    {"name": "Use of create_function()", "severity": 3, "message": "create_function() is essentially eval()", "impact": "Arbitrary code execution", "recommendation": "Use anonymous functions instead", "regex": r"\bcreate_function\s*\("},
    {"name": "Insecure cipher usage", "severity": 2, "message": "DES/RC4 via mcrypt_cbc or RC4 in openssl", "impact": "Broken confidentiality", "recommendation": "Use AES-GCM or sodium", "regex": r"mcrypt_cbc|RC4"},
    {"name": "Use of uniqid()", "severity": 2, "message": "uniqid() is predictable", "impact": "Guessable tokens", "recommendation": "Use random_int() or random_bytes()", "regex": r"\buniqid\s*\("},
    {"name": "Unvalidated redirect", "severity": 2, "message": "header('Location:') to external URL", "impact": "Open redirect / phishing", "recommendation": "Restrict to internal paths", "regex": r"header\s*\(\s*[\"']Location:.*https?://"},
    {"name": "Insecure cookie flags", "severity": 2, "message": "setcookie() without HttpOnly/Secure", "impact": "XSS can steal cookies", "recommendation": "Always set HttpOnly and Secure", "regex": r"setcookie\s*\([^,]+,[^,]+,(0|false)"},
    {"name": "Unvalidated JSONP callback", "severity": 2, "message": "JSONP without callback validation", "impact": "Cross-site content injection", "recommendation": "Whitelist callback names", "regex": r"json_encode\s*\(.*\)\s*;\s*\?"},
    {"name": "Unrestricted rmdir()", "severity": 3, "message": "rmdir() on user input", "impact": "Deletion of arbitrary directories", "recommendation": "Restrict directory names", "regex": r"\brmdir\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Use of popen()", "severity": 3, "message": "popen() can lead to command injection", "impact": "Arbitrary command execution", "recommendation": "Avoid or strictly sanitize inputs", "regex": r"\bpopen\s*\("},
    {"name": "Dynamic function call", "severity": 3, "message": "call_user_func() on user input", "impact": "Execution of sensitive functions", "recommendation": "Validate against an allowlist", "regex": r"call_user_func\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Remote require_once", "severity": 3, "message": "require_once() with URL", "impact": "Remote code execution", "recommendation": "Disable URL includes; restrict to local files", "regex": r"require_once\s*\(\s*[\'\"].*https?://"},
    {"name": "Use of escapeshellcmd/arg", "severity": 2, "message": "escapeshellcmd() or escapeshellarg() usage", "impact": "May still be bypassed, leading to shell injection", "recommendation": "Avoid shell calls or use safer APIs", "regex": r"(?:escapeshellcmd|escapeshellarg)\s*\("},
    {"name": "Use of parse_str()", "severity": 2, "message": "parse_str() can overwrite existing variables", "impact": "Variable pollution, possible code logic flaws", "recommendation": "Use filter_input_array() or manual parsing", "regex": r"\bparse_str\s*\("},
    {"name": "display_errors enabled", "severity": 1, "message": "display_errors is turned on", "impact": "Stack traces and sensitive info may leak", "recommendation": "Disable display_errors in production", "regex": r"ini_set\s*\(\s*[\'\"]display_errors[\'\"]\s*,\s*[\'\"]1[\'\"]"},
    {"name": "Weak JWT 'none' algorithm", "severity": 3, "message": "Accepting JWT with alg=none allows forgery", "impact": "Signature bypass, token forgery", "recommendation": "Enforce strong algorithms (HS256, RS256, etc.)", "regex": r"jwt.*alg\s*=\s*[\'\"]none[\'\"]"},
    {"name": "PHAR deserialization", "severity": 3, "message": "PharData or .phar include can trigger object injection", "impact": "PHP object injection, potential RCE", "recommendation": "Disable phar.readonly or avoid PHAR usage", "regex": r"\bPharData\b|\b\.phar\b"},
    {"name": "CORS wildcard origin", "severity": 2, "message": "Access-Control-Allow-Origin set to '*'", "impact": "Sensitive data exposed to any origin", "recommendation": "Restrict allowed origins", "regex": r"header\s*\(\s*[\'\"]Access-Control-Allow-Origin:\s*\*\s*[\'\"]"},
    {"name": "Unbounded fwrite() loop", "severity": 2, "message": "fwrite() inside loop w/o size checks", "impact": "Potential DoS or disk exhaustion", "recommendation": "Enforce write size limits", "regex": r"while\s*\([^)]*fwrite\("},
    {"name": "Unvalidated upload", "severity": 3, "message": "move_uploaded_file() without MIME/type checks", "impact": "Arbitrary file upload (webshells, etc.)", "recommendation": "Validate file type/extension before saving", "regex": r"\bmove_uploaded_file\s*\("},
    {"name": "Unvalidated Refresh redirect", "severity": 2, "message": "header('Refresh:') with user input", "impact": "Open redirect / phishing", "recommendation": "Restrict target URLs or remove Refresh headers", "regex": r"header\s*\(\s*[\'\"]Refresh:"},
    {"name": "Hard-coded DB credentials", "severity": 2, "message": "Plaintext DB password in code", "impact": "Credentials leakage if code is exposed", "recommendation": "Use env vars or secure vaults", "regex": r"\$db_(pass|password)\s*="},
    {"name": "Deprecated mysql_* usage", "severity": 2, "message": "Old mysql extension is unmaintained", "impact": "Lack of modern features & security", "recommendation": "Use PDO or MySQLi with prepared statements", "regex": r"\bmysql_[a-zA-Z_]+\s*\("},
    {"name": "stream_wrapper_register()", "severity": 3, "message": "Custom PHP stream wrapper registration", "impact": "May allow RFI/LFI-style behavior", "recommendation": "Avoid dynamic wrappers or validate inputs", "regex": r"\bstream_wrapper_register\s*\("},
    {"name": "Use of extract()", "severity": 2, "message": "extract() can overwrite variables", "impact": "Variable injection and logic flaws", "recommendation": "Assign variables explicitly instead", "regex": r"\bextract\s*\("},
    {"name": "XPath Injection", "severity": 3, "message": "Building XPath queries from user input", "impact": "Attackers can craft XPath to exfiltrate XML data", "recommendation": "Validate or escape all input used in XPath", "regex": r"\b(xpath)\s*\(\s*.*\$_(GET|POST|REQUEST)"},
    {"name": "XML External Entity (XXE)", "severity": 3, "message": "Loading XML from user input without disabling entities", "impact": "Local file read or SSRF via external entities", "recommendation": "Disable external entities (e.g. DOMDocument->resolveExternals = false)", "regex": r"\b(?:DOMDocument->loadXML|simplexml_load_string)\s*\(\s*\$_"},
    {"name": "Server-Side Template Injection", "severity": 3, "message": "Rendering templates with untrusted template names", "impact": "Remote code execution via template syntax", "recommendation": "Whitelist template names; do not pass raw user input", "regex": r"->render\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "LDAP Injection", "severity": 3, "message": "Building LDAP filter from user input", "impact": "Attackers can manipulate directory queries", "recommendation": "Escape LDAP filters or use parameterized APIs", "regex": r"ldap_(?:search|bind)\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Unsafe PDO execute()", "severity": 3, "message": "Passing superglobals directly to PDO->execute()", "impact": "Defeats prepared statement protections", "recommendation": "Bind parameters explicitly; avoid passing raw $_ arrays", "regex": r"->execute\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Email Header Injection", "severity": 3, "message": "Using user input in mail() headers", "impact": "Attackers can inject additional headers (Bcc:, etc.)", "recommendation": "Sanitize CRLF and restrict header values", "regex": r"\bmail\s*\([^,]+,[^,]+,[^,]+,[^,]+\$_(GET|POST|REQUEST)"},
    {"name": "PHPINFO Exposure", "severity": 1, "message": "Call to phpinfo()", "impact": "Exposes environment and configuration", "recommendation": "Remove phpinfo() calls in production", "regex": r"\bphpinfo\s*\("},
    {"name": "var_dump() on Superglobals", "severity": 1, "message": "Dumping superglobals directly", "impact": "Leaks internal data to clients", "recommendation": "Remove or guard var_dump() in production", "regex": r"\bvar_dump\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "parse_url() + file_get_contents()", "severity": 3, "message": "Parsing user URL then fetching it", "impact": "SSRF or local file read", "recommendation": "Validate scheme & host; restrict to safe URLs", "regex": r"\bparse_url\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "YAML Deserialization", "severity": 3, "message": "yaml_parse() or Yaml::parse() on user input", "impact": "Object injection via YAML", "recommendation": "Avoid parsing untrusted YAML", "regex": r"\b(?:yaml_parse|Yaml::parse)\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Config File Disclosure", "severity": 2, "message": "Accessing .env/.ini/.yaml files", "impact": "Credentials and secrets leak", "recommendation": "Do not expose config files; restrict file paths", "regex": r"\.(?:env|ini|ya?ml)"},
    {"name": "WebSocket Injection", "severity": 3, "message": "Initializing Ratchet App with user input", "impact": "Frame injection or hijacking", "recommendation": "Do not pass raw user input to WebSocket server", "regex": r"new\s+Ratchet\\App\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Weak password_hash() options", "severity": 2, "message": "Low cost or missing algorithm options", "impact": "Weak password hashes", "recommendation": "Use PASSWORD_DEFAULT with higher cost", "regex": r"password_hash\s*\(.*?(PASSWORD_DEFAULT|PASSWORD_BCRYPT)\s*,\s*\[.*?[\"']cost[\"']\s*=>\s*\d"},
    {"name": "PHAR Static Usage", "severity": 3, "message": "Any use of Phar:: class", "impact": "PHAR metadata can trigger object injection", "recommendation": "Disable PHAR or avoid includes", "regex": r"\bPhar::"},
    {"name": "Missing SSL peer verification", "severity": 2, "message": "CURLOPT_SSL_VERIFYPEER not set to true", "impact": "MITM attacks due to unverified certificates", "recommendation": "Always set CURLOPT_SSL_VERIFYPEER = true", "regex": r"curl_setopt\s*\(\s*\$[a-zA-Z_]\w*\s*,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)\s*\)"},
    {"name": "Unsafe assert() use", "severity": 3, "message": "assert() called on user input", "impact": "Arbitrary code execution via evaluated expression", "recommendation": "Avoid assert(); use strict validation", "regex": r"\bassert\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Insecure password_verify() use", "severity": 2, "message": "password_verify() without hash_equals()", "impact": "Timing attacks may leak correct hash", "recommendation": "Compare hashes with hash_equals()", "regex": r"\bpassword_verify\s*\([^,]+,[^,]+\)\s*(?!.*hash_equals)"},
    {"name": "Missing SameSite cookie flag", "severity": 2, "message": "setcookie() without SameSite attribute", "impact": "CSRF risk due to lax cookie policy", "recommendation": "Add 'samesite' => 'Lax' or 'Strict' in options", "regex": r"\bsetcookie\s*\([^,]+,[^,]+\)(?!.*,.*samesite)"},
    {"name": "Insecure header exposure", "severity": 1, "message": "header('X-Powered-By') present", "impact": "Leaking framework/PHP version information", "recommendation": "Remove or disable X-Powered-By header", "regex": r"header\s*\(\s*[\"']X-Powered-By:"},
    {"name": "session_decode() on user data", "severity": 3, "message": "session_decode() with untrusted input", "impact": "Session hijacking/object injection", "recommendation": "Avoid session_decode(); use session_start() only", "regex": r"\bsession_decode\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Deprecated call_user_method()", "severity": 2, "message": "call_user_method() may allow dynamic invocation", "impact": "Arbitrary method execution", "recommendation": "Use direct method calls or call_user_func() safely", "regex": r"\bcall_user_method\s*\("},
    {"name": "Unchecked header_remove()", "severity": 2, "message": "header_remove() may drop critical security headers", "impact": "Security headers can be disabled by attacker input", "recommendation": "Validate header names before removal", "regex": r"\bheader_remove\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Eval in templating engine", "severity": 3, "message": "eval() used in template processing", "impact": "Remote code execution via template injection", "recommendation": "Use built-in safe templating methods", "regex": r"\beval\s*\(.*(Twig|Smarty).*?\)"},
    {"name": "Wildcard file inclusion", "severity": 3, "message": "glob() on user-supplied pattern", "impact": "LFI/RFI via uncontrolled glob patterns", "recommendation": "Sanitize and restrict glob patterns", "regex": r"\bglob\s*\(\s*\$_(GET|POST|REQUEST)"},
    {"name": "Unbounded readfile() loop", "severity": 2, "message": "readfile() inside loop without size checks", "impact": "Potential DoS or disk exhaustion", "recommendation": "Limit iterations or check file size before reading", "regex": r"while\s*\([^)]*readfile\("},
    {"name": "Dynamic DB table name", "severity": 3, "message": "Using $_GET['table'] directly in SQL FROM clause", "impact": "SQL injection and schema enumeration", "recommendation": "Whitelist table names and use prepared statements", "regex": r"FROM\s+\$_(GET|POST|REQUEST)\s*\["},
    {"name": "Unsafe Set-Cookie header", "severity": 2, "message": "header('Set-Cookie') with user input", "impact": "Cookie spoofing or hijacking", "recommendation": "Use setcookie() and sanitize values", "regex": r"header\s*\(\s*[\"']Set-Cookie:.*\$_(GET|POST|REQUEST)"},
    {'name': 'FTP File Transfer from User Input','severity':3,'message':'ftp_* functions on user input','impact':'Command injection/file transfer misuse','recommendation':'Validate or avoid FTP-based input','regex':r'\bftp_(?:get|put|connect)\s*\(\s*\$_(GET|POST|REQUEST)'},
    {'name': 'Preg_replace /e Modifier','severity':3,'message':'preg_replace with /e modifier','impact':'Remote code execution via regex evaluation','recommendation':'Remove /e or use preg_replace_callback','regex':r'preg_replace\s*\(\s*["\'][^"\'/]+/e'},
    {'name': 'Backtick Shell Execution','severity':3,'message':'Backtick operator used with user input','impact':'Command injection','recommendation':'Avoid backticks and use safer APIs','regex':r'`[^`]*\$_(GET|POST|REQUEST)[^`]*`'},
    {'name': 'Variable Variables','severity':2,'message':'Use of variable variables ($$var)','impact':'Code injection or unexpected behavior','recommendation':'Avoid $$; use arrays or fixed identifiers','regex':r'\$\$\w+'},
    {'name': 'ReflectionClass from User Input','severity':3,'message':'ReflectionClass instantiated with user input','impact':'Arbitrary class instantiation','recommendation':'Whitelist classes before reflecting','regex':r'ReflectionClass\s*\(\s*\$_(GET|POST|REQUEST)'},
    {'name': 'Directory Scan from User Input','severity':2,'message':'scandir() on user input','impact':'Directory enumeration or LFI','recommendation':'Validate and whitelist directory paths','regex':r'scandir\s*\(\s*\$_(GET|POST|REQUEST)'},
    {'name': 'Unvalidated parse_ini_file','severity':2,'message':'parse_ini_file() on user input','impact':'Insecure disclosure of config files','recommendation':'Restrict file names and paths','regex':r'parse_ini_file\s*\(\s*\$_(GET|POST|REQUEST)'},
    {'name': 'Error Log Injection','severity':2,'message':'error_log() called with user input','impact':'Log injection or poisoning','recommendation':'Sanitize data before logging','regex':r'error_log\s*\(\s*\$_(GET|POST|REQUEST)'},
    {'name': "Allow URL fopen Enabled","severity":2,'message':'allow_url_fopen is enabled','impact':'File inclusion via URL possible','recommendation':'Disable URL fopen for security','regex':r'ini_set\s*\(\s*[\'"]allow_url_fopen[\'"]\s*,\s*[\'"](?:1|On|True)'},
    {'name': 'Debug Function on Superglobals','severity':1,'message':'var_export()/print_r() on superglobals','impact':'Information disclosure','recommendation':'Remove debug functions in production','regex':r'\b(?:var_export|print_r)\s*\(\s*\$_(GET|POST|REQUEST)'},
    {"name": "PHP.RegisterGlobals.Enabled", "severity": 3, "message": "Deprecated PHP directive register_globals is enabled in the code or configuration.", "impact": "Automatically importing user input into global variables can lead to variable poisoning and arbitrary manipulation of application state.", "recommendation": "Disable register_globals in php.ini or .htaccess and refactor code to explicitly initialize and validate input from $_GET/$_POST.", "regex": r"(?i)(?:ini_set\s*\(\s*['\"]register_globals['\"]\s*,\s*['\"](?:On|1)['\"]\s*\)|\bregister_globals\b\s*=\s*(?:On|1)\b|php_flag\s+register_globals\s+on)"},
    {"name": "PHP.AllowUrlInclude.Enabled", "severity": 2, "message": "Insecure PHP setting allow_url_include is enabled, permitting inclusion of remote URLs.", "impact": "Remote file inclusion becomes possible if user input is passed to include/require, potentially allowing attackers to execute external code.", "recommendation": "Keep allow_url_include disabled. Do not include files from untrusted sources; include only local files and validate file paths.", "regex": r"(?i)(?:ini_set\s*\(\s*['\"]allow_url_include['\"]\s*,\s*['\"](?:On|1)['\"]\s*\)|\ballow_url_include\b\s*=\s*(?:On|1)\b|php_flag\s+allow_url_include\s+on)"},
    {"name": "PHP.DisplayStartupErrors.On", "severity": 1, "message": "display_startup_errors (PHP error display) is enabled, potentially exposing debug info.", "impact": "Detailed PHP errors or startup warnings may reveal server paths, configuration, or other sensitive information to an attacker.", "recommendation": "Turn off display_startup_errors (and display_errors) in production. Use error logging to record issues, without showing errors to users.", "regex": r"(?i)(?:ini_set\s*\(\s*['\"]display_startup_errors['\"]\s*,\s*['\"](?:On|1)['\"]\s*\)|\bdisplay_startup_errors\b\s*=\s*(?:On|1)\b|php_flag\s+display_startup_errors\s+on)"},
    {"name": "PHP.UnvalidatedRedirect", "severity": 2, "message": "User-controlled redirect detected (potential open redirect vulnerability).", "impact": "Unvalidated redirects allow attackers to redirect users to malicious sites or unexpectedly skip access controls, facilitating phishing or abuse of trust.", "recommendation": "Avoid using user input directly in header(\"Location\"). Validate redirect targets against a whitelist or use relative URLs/internal routes only.", "regex": r"header\s*\(\s*['\"]Location[^)]*\$_(?:GET|REQUEST)\["},
    {"name": "PHP.MissingCSRFToken", "severity": 3, "message": "Form or request handler appears to lack CSRF token validation (possible CSRF vulnerability).", "impact": "Without anti-CSRF tokens, attackers can forge requests on behalf of users, potentially performing unauthorized state-changing actions in the user’s session.", "recommendation": "Implement CSRF protection: include a hidden token in forms and verify it on the server for each state-changing request. Utilize framework CSRF guards or libraries.", "regex": r"(?si)<form\b(?:(?!csrf).)*</form>"},
    {"name": "PHP.PrivilegeEscalation.Input", "severity": 3, "message": "User input is used to control roles/privileges (potential privilege escalation flaw).", "impact": "Trusting user-provided fields (e.g., 'role' or 'privilege' parameters) can allow attackers to elevate their permissions or access other users’ data by modifying those values.", "recommendation": "Never use client-side input to set user roles or privileges. Enforce server-side access control checks and ignore or validate any role/privilege fields in requests.", "regex": r"(?i)\$_(?:GET|POST|REQUEST)\[\s*['\"](?:(?:user_)?role|privilege|privileges|is_admin)['\"]\]"},
    {"name": "PHP.PermissiveFilePermissions", "severity": 2, "message": "Detected use of overly permissive file permissions (e.g., chmod or mkdir with 0777).", "impact": "World-writable or world-executable permissions (777) allow any user or process on the system to modify or execute those files, leading to possible code tampering or information disclosure.", "recommendation": "Use restrictive file permissions. Avoid 0777; instead assign the minimal required rights (e.g., 755 for directories, 644 for files) and disable directory indexing to protect sensitive files.", "regex": r"(?i)(?:\b(?:chmod|mkdir)\s*\([^,]+,\s*0?777\b|chmod\s+777\b|umask\s*\(0\s*\))"},
    {"name":"OS Command Injection via shell_exec","severity":3,"message":"shell_exec() on user input","impact":"Arbitrary code execution","recommendation":"Sanitize inputs or avoid shell_exec()","regex":r"(system|exec|passthru|shell_exec)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Dynamic File Inclusion (require/include)","severity":3,"message":"include/require on user input","impact":"LFI/RFI code execution","recommendation":"Validate & whitelist include paths","regex":r"\b(?:include|include_once|require|require_once)\s*\([^)]*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name":"Unrestricted File Upload","severity":3,"message":"move_uploaded_file() on user input","impact":"Arbitrary file upload / webshell","recommendation":"Validate file type/extension & restrict upload paths","regex":r"move_uploaded_file\s*\(.*\$_FILES\["},
    {"name":"Reflected XSS via print/printf","severity":2,"message":"print/printf() on user input","impact":"Arbitrary JS execution","recommendation":"Escape output via htmlspecialchars()","regex":r"\b(?:print|printf)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"XSS via echo without sanitization","severity":2,"message":"echo of user data without htmlspecialchars()","impact":"Arbitrary JS execution","recommendation":"Use htmlspecialchars() or strip_tags()","regex":r"\becho\s+((?!htmlspecialchars).)*\$_(?:GET|POST|REQUEST)"},
    {"name":"Stored XSS via variable echo","severity":3,"message":"Echo of a user-controlled variable","impact":"Stored XSS / Arbitrary JS execution","recommendation":"Sanitize and escape all stored user data","regex":r"\$([A-Za-z_]\w*)\s*=\s*\$_(?:GET|POST|REQUEST)\[[^\]]+\];[^}]*echo\s+[^;]*\$\1\b"},
    {"name":"Backtick Shell Execution","severity":3,"message":"Backtick operator used with user input","impact":"Command injection","recommendation":"Avoid backticks; use safer APIs","regex":r"`[^`]*\$_(?:GET|POST|REQUEST)[^`]*`"},
    {"name":"popen/proc_open Injection","severity":3,"message":"popen()/proc_open() on user input","impact":"Arbitrary command execution","recommendation":"Sanitize inputs; avoid these functions","regex":r"\b(?:popen|proc_open)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"FTP Transfer from User Input","severity":3,"message":"ftp_* functions on user input","impact":"Command injection/file transfer misuse","recommendation":"Validate or avoid FTP-based input","regex":r"\bftp_(?:get|put|connect)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"preg_replace /e Modifier","severity":3,"message":"/e modifier in preg_replace","impact":"RCE via regex evaluation","recommendation":"Use preg_replace_callback()","regex":r"preg_replace\s*\(\s*['\"][^'\"]+/e"},
    {"name":"Open Redirect via header('Location')","severity":2,"message":"header('Location:') with user input","impact":"Phishing redirect","recommendation":"Whitelist redirect URLs","regex":r"header\s*\(\s*['\"]Location:[^)]*\$_(?:GET|POST|REQUEST)"},
    {"name":"Directory Traversal in file operations","severity":2,"message":"Potential ../ in include/file functions","impact":"Restricted file access","recommendation":"Normalize & block ../ sequences","regex":r"\b(?:include|require|fopen|file_get_contents|readfile)\s*\([^)]*\.\./"},
    {"name":"Debug Dump of Superglobals","severity":1,"message":"var_dump()/print_r()/var_export() on superglobals","impact":"Information disclosure","recommendation":"Remove debug functions in production","regex":r"\b(?:var_dump|print_r|var_export)\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"JSONP Callback Injection","severity":2,"message":"Unvalidated JSONP callback","impact":"Cross-site content injection","recommendation":"Whitelist callback names","regex":r"json_encode\s*\(.*\)\s*;\s*\?"},
    {"name":"Unserialize on user input","severity":3,"message":"unserialize() on user input","impact":"PHP object injection","recommendation":"Avoid unserialize() on untrusted data","regex":r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Use of $_REQUEST Superglobal","severity":2,"message":"Use of $_REQUEST (may include GET/POST/COOKIE)","impact":"Uncontrolled input sources","recommendation":"Use explicit superglobals ($_GET/$_POST/$_COOKIE)","regex":r"\$_REQUEST\b"},
    {"name":"Session Fixation via session_id","severity":2,"message":"session_id() called with user input","impact":"Session fixation","recommendation":"Regenerate session ID server-side","regex":r"\bsession_id\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"die()/exit() with user input","severity":2,"message":"die()/exit() on user input","impact":"Arbitrary output injection","recommendation":"Escape output or avoid exit/die with unsanitized input","regex":r"\b(?:die|exit)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection (PostgreSQL/Oracle/MSSQL)","severity":3,"message":"DB query on user input","impact":"DB compromise","recommendation":"Use prepared statements","regex":r"\b(?:pg_query|pg_exec|oci_execute|sqlsrv_query)\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection via sqlsrv_execute","severity":3,"message":"sqlsrv_execute() on user input","impact":"DB compromise","recommendation":"Use parameterized queries","regex":r"\bsqlsrv_execute\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection via oci_parse","severity":3,"message":"oci_parse() on user input","impact":"DB compromise","recommendation":"Use parameterized queries","regex":r"\boci_parse\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"SSRF via fsockopen","severity":3,"message":"fsockopen() on user input","impact":"SSRF","recommendation":"Validate hostnames; use allowlist","regex":r"\bfsockopen\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SSRF via stream_socket_client","severity":3,"message":"stream_socket_client() on user input","impact":"SSRF","recommendation":"Validate hostnames; use allowlist","regex":r"\bstream_socket_client\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"XML External Entity via simplexml_load_file","severity":3,"message":"simplexml_load_file() on user input","impact":"XXE / file disclosure","recommendation":"Disable external entities; validate input","regex":r"\bsimplexml_load_file\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"XML External Entity via DOMDocument load","severity":3,"message":"DOMDocument->load() on user input","impact":"XXE / file disclosure","recommendation":"Disable external entities; validate input","regex":r"\bDOMDocument->load\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Source Disclosure via highlight_file","severity":2,"message":"highlight_file() on user input","impact":"Code disclosure","recommendation":"Remove or sanitize file parameter","regex":r"\bhighlight_file\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Source Disclosure via show_source","severity":2,"message":"show_source() on user input","impact":"Code disclosure","recommendation":"Remove or sanitize file parameter","regex":r"\bshow_source\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Environment Injection via putenv","severity":2,"message":"putenv() on user input","impact":"Environment manipulation","recommendation":"Avoid putenv() with untrusted data","regex":r"\bputenv\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Filesystem Manipulation via mkdir/chmod","severity":3,"message":"mkdir()/chmod() on user input","impact":"FS manipulation","recommendation":"Validate paths; restrict input","regex":r"\b(?:mkdir|chmod)\s*\([^,]*\$_(?:GET|POST|REQUEST)"},
    {"name":"Unserialize on user input","severity":3,"message":"unserialize() on user input","impact":"PHP object injection","recommendation":"Avoid unserialize(); use json_decode()","regex":r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Session Fixation via session_id","severity":2,"message":"session_id() called with user input","impact":"Session fixation","recommendation":"Regenerate session ID server‑side","regex":r"\bsession_id\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Session Naming via session_name","severity":2,"message":"session_name() on user input","impact":"Session hijacking","recommendation":"Avoid session_name() with untrusted data","regex":r"\bsession_name\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"PDO execute on user input","severity":3,"message":"PDO execute() on user input","impact":"DB compromise","recommendation":"Bind parameters explicitly","regex":r"->execute\s*\(.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection (blacklist‑based)","severity": 3,"message": "Suspicious SQL keywords or tokens detected","impact": "Potential SQL injection attempt","recommendation": "Use parameterized queries instead of relying on regex filtering","regex": r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b|--|#|/\*|\*/|;|\bOR\b|\bAND\b"},
    {"name":"SQL Injection (superglobal in query)","severity":3,"message":"Unescaped superglobal used directly in query function","impact":"DB compromise","recommendation":"Use prepared statements with bound parameters","regex":r"\b(?:mysql_query|mysqli_query|PDO->query|PDO->exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name":"SQL Injection via concatenation","severity":3,"message":"SQL query built by concatenating user input","impact":"DB compromise","recommendation":"Use parameterized queries; do not concatenate user data","regex":r"\b(?:mysql_query|mysqli_query|PDO->query|PDO->exec)\s*\(\s*[^)]*\.\s*\$[A-Za-z_]\w*"},
    {"name":"SQL Injection via interpolation","severity":3,"message":"User input interpolated inside double‑quoted SQL string","impact":"DB compromise","recommendation":"Use bound parameters instead of interpolation","regex":r"->(?:query|exec)\s*\(\s*\"[^\"]*\$_(?:GET|POST|REQUEST)[^\"]*\""},
    {"name":"SQL Injection in prepare()","severity":3,"message":"PDO->prepare() called on a query string containing user input","impact":"Defeats the purpose of prepared statements","recommendation":"Use parameter placeholders, do not embed variables directly","regex":r"\bPDO->prepare\s*\(\s*[\"'][^\"']*\$_(?:GET|POST|REQUEST)[^\"']*[\"']"},
    {"name":"SQL Injection (fallback blacklist)","severity":3,"message":"Suspicious SQL keywords or tokens detected","impact":"Potential SQL injection attempt","recommendation":"Use parameterized queries instead of regex filtering","regex":r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b|--|#|/\*|\*/|;|\bOR\b|\bAND\b"},
    {"name":"SQL Injection via tautology","severity":3,"message":"OR 1=1 pattern detected","impact":"DB compromise","recommendation":"Use parameterized queries; do not allow tautologies","regex":r"\bOR\s+1\s*=\s*1\b"},
    {"name":"SQL Injection via stacked queries","severity":3,"message":"Multiple SQL statements detected","impact":"Stacked query injection","recommendation":"Disable multiple statements","regex":r";\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b"},
    {"name":"SQL Injection via time-based functions","severity":3,"message":"SLEEP or BENCHMARK in query","impact":"Time-based blind SQLi","recommendation":"Use prepared statements and limit allowed functions","regex":r"\b(?:SLEEP|BENCHMARK)\s*\("},
    {"name":"SQL Injection via UNION SELECT","severity":3,"message":"UNION SELECT injection attempt","impact":"Data exfiltration","recommendation":"Use bound parameters; reject unions","regex":r"\bUNION\s+SELECT\b"},
    {"name":"SQL Injection via LOAD_FILE","severity":3,"message":"LOAD_FILE function in query","impact":"Local file read","recommendation":"Disable these functions or restrict queries","regex":r"\bLOAD_FILE\s*\("},
    {"name":"SQL Injection via information_schema","severity":3,"message":"Access to information_schema tables","impact":"Schema enumeration","recommendation":"Use least privilege; avoid dynamic queries","regex":r"\binformation_schema\."},
    {"name":"SQL Injection via sprintf","severity":3,"message":"sprintf used to build SQL with user input","impact":"DB compromise","recommendation":"Use prepared statements","regex":r"\bsprintf\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST).*['\"]\s*,?"},
    {"name":"SQL Injection via mysqli_multi_query","severity":3,"message":"mysqli_multi_query() with user input","impact":"Stacked query injection","recommendation":"Use single‐statement execution","regex":r"\bmysqli_multi_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name":"SQL Injection via PDO exec multiple","severity":3,"message":"PDO exec() with multiple statements","impact":"Stacked query injection","recommendation":"Use single statements","regex":r"\bPDO->exec\s*\(\s*[^)]*;[^)]*\)"},
    {"name":"SQL Injection via Doctrine createQuery","severity":3,"message":"createQuery() with untrusted input","impact":"DB compromise","recommendation":"Use parameter binding","regex":r"\bcreateQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection via OUTFILE","severity":3,"message":"INTO OUTFILE injection","impact":"File writes on server","recommendation":"Disallow INTO OUTFILE usage","regex":r"\bINTO\s+OUTFILE\b"},
    {"name":"SQL Injection via DUMPFILE","severity":3,"message":"INTO DUMPFILE injection","impact":"File writes on server","recommendation":"Disallow INTO DUMPFILE usage","regex":r"\bINTO\s+DUMPFILE\b"},
    {"name":"SQL Injection via EXEC","severity":3,"message":"EXEC/EXECUTE used in query string","impact":"Dynamic SQL execution","recommendation":"Use parameterized queries","regex":r"\bEXEC(?:UTE)?\s*\("},
    {"name":"SQL Injection via xp_cmdshell","severity":3,"message":"xp_cmdshell usage in query","impact":"Remote command execution","recommendation":"Disable xp_cmdshell","regex":r"\bxp_cmdshell\b"},
    {"name":"SQL Injection via WAITFOR DELAY","severity":3,"message":"WAITFOR DELAY used in query","impact":"Time‑based blind SQLi","recommendation":"Use parameterized queries","regex":r"\bWAITFOR\s+DELAY\b"},
    {"name":"SQL Injection via PG_SLEEP","severity":3,"message":"PG_SLEEP used in query","impact":"Time‑based blind SQLi","recommendation":"Use parameterized queries","regex":r"\bPG_SLEEP\s*\("},
    {"name":"SQL Injection via INFORMATION_SCHEMA","severity":3,"message":"information_schema metadata access","impact":"Schema enumeration","recommendation":"Use least privilege","regex":r"\binformation_schema\.(?:TABLES|COLUMNS)\b"},
    {"name":"SQL Injection via CONCAT","severity":3,"message":"CONCAT used with user input in query","impact":"Dynamic SQL building","recommendation":"Use bound parameters","regex":r"\bCONCAT\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection via REGEXP","severity":3,"message":"REGEXP used with user input","impact":"Regex‑based injection","recommendation":"Use prepared statements","regex":r"\bREGEXP\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Injection via LIKE","severity":3,"message":"LIKE wildcard used with user input","impact":"Pattern‑based SQLi","recommendation":"Use parameterized queries","regex":r"\bLIKE\s*['\"].*\$_(?:GET|POST|REQUEST)[^'\"']*['\"]"},
    {"name": "setInterval string eval",                "severity": 3, "message": "setInterval with string + user input",               "impact": "Arbitrary JS execution",       "recommendation": "Use function references, not strings",  "regex": r"setInterval\s*\(\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "setTimeout string eval",                 "severity": 3, "message": "setTimeout with string + user input",                "impact": "Arbitrary JS execution",       "recommendation": "Use function references, not strings",  "regex": r"setTimeout\s*\(\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "element.setAttribute injection",         "severity": 3, "message": "setAttribute(name, user input)",                     "impact": "DOM‑based XSS via attribute",  "recommendation": "Validate attribute names & values",     "regex": r"\.setAttribute\s*\(\s*['\"][^'\"]+['\"],\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "inline style backgroundImage",           "severity": 2, "message": "element.style.backgroundImage with user data",       "impact": "CSS‑based XSS",              "recommendation": "Sanitize CSS or avoid inline styles",    "regex": r"\.style\.backgroundImage\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "CSS url() injection",                    "severity": 2, "message": "CSS url() containing user input",                   "impact": "CSS XSS or resource load",    "recommendation": "Validate & sanitize URLs in CSS",       "regex": r"url\s*\(\s*['\"]?[^)'\"]*\$_(?:GET|POST|REQUEST)[^)'\"]*['\"]?\)"},
    {"name": "meta refresh injection",                 "severity": 3, "message": "<meta http-equiv=refresh> with user URL",       "impact": "Redirect‑based XSS/Phishing",  "recommendation": "Disallow untrusted meta redirects",     "regex": r"<meta\b[^>]*http-equiv\s*=\s*['\"]refresh['\"][^>]*content\s*=\s*['\"][^'\">]*url=\s*\$_(?:GET|POST|REQUEST)[^'\">]*['\"]"},
    {"name": "img src attribute injection",            "severity": 3, "message": "<img src=user input>",                           "impact": "Scriptable URI XSS",          "recommendation": "Disallow js: URIs & validate URLs",      "regex": r"<img\b[^>]*\bsrc\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "iframe src injection",                   "severity": 3, "message": "<iframe src=user input>",                       "impact": "DOM‑based XSS via frame",      "recommendation": "Whitelist & sanitize frame URLs",        "regex": r"<iframe\b[^>]*\bsrc\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "embed src injection",                    "severity": 3, "message": "<embed src=user input>",                        "impact": "Media XSS vector",            "recommendation": "Validate embed sources",                "regex": r"<embed\b[^>]*\bsrc\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "object data injection",                  "severity": 3, "message": "<object data=user input>",                      "impact": "Object‑based XSS",            "recommendation": "Validate object data URIs",            "regex": r"<object\b[^>]*\bdata\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "svg <use> xlink:href injection",         "severity": 3, "message": "SVG <use> xlink:href with user data",             "impact": "SVG‑based XSS",              "recommendation": "Sanitize SVG attributes",             "regex": r"xlink:href\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "srcset attribute injection",             "severity": 3, "message": "<img srcset=user input>",                        "impact": "Responsive image XSS",        "recommendation": "Validate all image sets",             "regex": r"srcset\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "meta CSP bypass header",                 "severity": 2, "message": "Content-Security-Policy header with user input",   "impact": "CSP bypass risk",             "recommendation": "Do not include user input in CSPs",    "regex": r"header\s*\(\s*['\"]Content-Security-Policy:.*\$_(?:GET|POST|REQUEST)"},
    {"name": "location.assign() injection",            "severity": 3, "message": "location.assign(user input)",                      "impact": "Client‑side redirect XSS",    "recommendation": "Validate redirect URLs",               "regex": r"location\.assign\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "location.replace() injection",           "severity": 3, "message": "location.replace(user input)",                     "impact": "Client‑side redirect XSS",    "recommendation": "Validate redirect URLs",               "regex": r"location\.replace\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "location.hash assignment",               "severity": 2, "message": "location.hash = user input",                      "impact": "Fragment‑based XSS",         "recommendation": "Sanitize hash values",                 "regex": r"location\.hash\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name": "history.pushState injection",            "severity": 2, "message": "history.pushState(user input)",                    "impact": "URL‑based XSS risk",         "recommendation": "Validate state & URLs",                "regex": r"history\.pushState\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "history.replaceState injection",         "severity": 2, "message": "history.replaceState(user input)",                 "impact": "URL‑based XSS risk",         "recommendation": "Validate state & URLs",                "regex": r"history\.replaceState\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "postMessage() injection",                "severity": 3, "message": "postMessage(user data)",                            "impact": "Cross‑window XSS risk",       "recommendation": "Validate & stringify payloads",         "regex": r"\.postMessage\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "createContextualFragment injection",     "severity": 3, "message": "createContextualFragment with user data",          "impact": "DOM‑based XSS",              "recommendation": "Sanitize fragment content",            "regex": r"createContextualFragment\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "script via createElement/src",           "severity": 3, "message": "document.createElement('script') + .src=user data", "impact": "Dynamic script injection",     "recommendation": "Disallow dynamic script src from input","regex": r"document\.createElement\s*\(\s*['\"]script['\"]\)\s*;?\s*.*\.src\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name": "element.onclick assignment",             "severity": 3, "message": "element.onclick = user input",                     "impact": "Event‑handler XSS",          "recommendation": "Avoid direct handler assignment",       "regex": r"\w+\.onclick\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name": "jQuery prepend() injection",             "severity": 3, "message": "jQuery prepend(user input)",                       "impact": "DOM‑based XSS",              "recommendation": "Escape HTML before prepending",       "regex": r"\.prepend\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "jQuery before() injection",              "severity": 3, "message": "jQuery before(user input)",                        "impact": "DOM‑based XSS",              "recommendation": "Escape HTML before insertion",       "regex": r"\.before\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "jQuery after() injection",               "severity": 3, "message": "jQuery after(user input)",                         "impact": "DOM‑based XSS",              "recommendation": "Escape HTML before insertion",       "regex": r"\.after\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "Mustache triple-stache injection",       "severity": 3, "message": "{{{ user data }}} raw injection in templates",      "impact": "Template XSS",              "recommendation": "Use escaped interpolation",           "regex": r"\{\{\{\s*.*\$_(?:GET|POST|REQUEST).*?\}\}\}"},
    {"name": "Blade raw directive injection",          "severity": 3, "message": "{!! user data !!} in Blade templates",           "impact": "Server‑side template XSS",   "recommendation": "Use {{ }} escapes in Blade",         "regex": r"\{!!\s*.*\$_(?:GET|POST|REQUEST)[^}]*!!\}"},
    {"name": "Angular $sce.trustAsHtml misuse",        "severity": 3, "message": "$sce.trustAsHtml(user input)",                "impact": "Bypasses Angular sanitization",   "recommendation": "Avoid trusting raw HTML",        "regex": r"\$sce\.trustAsHtml\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name": "React createElement dangerouslySet",     "severity": 3, "message": "React.createElement + dangerouslySetInnerHTML",    "impact": "React XSS risk",            "recommendation": "Avoid dangerouslySetInnerHTML",       "regex": r"React\.createElement\s*\(\s*['\"].*['\"].*dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name": "Vue v-bind:innerHTML injection",         "severity": 3, "message": "v-bind:innerHTML with user data",                  "impact": "Vue XSS risk",              "recommendation": "Use v-text or sanitize",             "regex": r"v-bind:innerHTML\s*=\s*['\"].*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name": "Vue v-for key injection",                "severity": 2, "message": "v-for key using user input",                      "impact": "Template instability",       "recommendation": "Use stable keys, not user data",      "regex": r"v-for\s*=\s*['\"].*\sin\s.*\skey\s*=\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name": "Reactive interpolation XSS",             "severity": 2, "message": "Template interpolation with user data",           "impact": "Client‑side XSS",            "recommendation": "Escape or sanitize inside {{ }}",   "regex": r"\{\{\s*.*\$_(?:GET|POST|REQUEST).*?\}\}"},
    {"name": "SELECT … FROM with user input",     "severity": 3, "message": "User input in SELECT clause or before FROM",          "impact": "Data exfiltration via SQL injection",        "recommendation": "Use prepared statements and bind parameters",    "regex": r"\bSELECT\b[\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?\bFROM\b"},
    {"name": "INSERT INTO with user input",       "severity": 3, "message": "User input in INSERT INTO statement",                "impact": "Data manipulation via SQL injection",      "recommendation": "Use prepared INSERT with bound values",       "regex": r"\bINSERT\s+INTO\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "UPDATE … SET with user input",      "severity": 3, "message": "User input in UPDATE SET clause",                   "impact": "Data manipulation via SQL injection",      "recommendation": "Use prepared UPDATE with bound values",     "regex": r"\bUPDATE\b[\s\S]*\bSET\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "DELETE FROM with user input",       "severity": 3, "message": "User input in DELETE FROM statement",                "impact": "Data deletion via SQL injection",         "recommendation": "Use prepared DELETE with bound parameters", "regex": r"\bDELETE\s+FROM\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "WHERE clause injection",            "severity": 3, "message": "User input in WHERE clause",                        "impact": "Conditional SQL injection",              "recommendation": "Bind WHERE parameters explicitly",            "regex": r"\bWHERE\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "ORDER BY injection",                "severity": 2, "message": "User input in ORDER BY clause",                     "impact": "Order manipulation / SQL injection",      "recommendation": "Whitelist sortable columns",                 "regex": r"\bORDER\s+BY\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "GROUP BY injection",                "severity": 2, "message": "User input in GROUP BY clause",                     "impact": "Aggregation injection risk",              "recommendation": "Whitelist group columns",                   "regex": r"\bGROUP\s+BY\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "HAVING clause injection",           "severity": 2, "message": "User input in HAVING clause",                       "impact": "Conditional aggregation injection",       "recommendation": "Bind HAVING parameters explicitly",           "regex": r"\bHAVING\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "LIMIT clause injection",            "severity": 2, "message": "User input in LIMIT clause",                        "impact": "Row‑count manipulation / SQL injection",   "recommendation": "Validate numeric bounds",                   "regex": r"\bLIMIT\b\s*\$_(?:GET|POST|REQUEST)"},
    {"name": "SUBSTRING() injection",             "severity": 3, "message": "User input in SUBSTRING() function",                "impact": "Error‑ or blind‑based SQL injection",     "recommendation": "Parameterize SUBSTRING arguments",         "regex": r"SUBSTRING\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name": "CHAR() injection",                  "severity": 3, "message": "User input in CHAR() function",                     "impact": "Obfuscated SQL injection",                "recommendation": "Parameterize CHAR arguments",             "regex": r"CHAR\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name": "CONCAT() injection",                "severity": 3, "message": "User input in CONCAT() function",                   "impact": "String‑based SQL injection",               "recommendation": "Use CONCAT via bound values",             "regex": r"CONCAT\s*\([\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "CAST/CONVERT injection",            "severity": 3, "message": "User input in CAST() or CONVERT()",                 "impact": "Type‑casting SQL injection",               "recommendation": "Parameterize CAST/CONVERT inputs",         "regex": r"\b(?:CAST|CONVERT)\s*\([\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "LOAD_FILE() injection",             "severity": 3, "message": "User input in LOAD_FILE() function",                "impact": "File read via SQL injection",             "recommendation": "Avoid dynamic file reads; validate input",  "regex": r"LOAD_FILE\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name": "GROUP_CONCAT() injection",          "severity": 3, "message": "User input in GROUP_CONCAT() function",             "impact": "Aggregated string‑based SQL injection",   "recommendation": "Parameterize GROUP_CONCAT inputs",         "regex": r"GROUP_CONCAT\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name": "JSON_EXTRACT() injection",          "severity": 2, "message": "User input in JSON_EXTRACT()",                      "impact": "Hybrid JSON/SQL injection",               "recommendation": "Parameterize JSON_EXTRACT inputs",         "regex": r"JSON_EXTRACT\s*\([\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "XML function injection",            "severity": 2, "message": "User input in EXTRACTVALUE()/UPDATEXML()",          "impact": "Error‑based SQL injection via XML",        "recommendation": "Parameterize XML function args",          "regex": r"(?:EXTRACTVALUE|UPDATEXML)\s*\([\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name": "Backtick identifier injection",     "severity": 2, "message": "User input inside backtick‑quoted identifiers",     "impact": "Identifier‑level SQL injection",           "recommendation": "Whitelist identifiers; avoid dynamic backticks", "regex": r"`[^`]*\$_(?:GET|POST|REQUEST)[^`]*`"},
    {"name": "Comment‑based injection",           "severity": 2, "message": "User input in SQL comments (-- or /*)",              "impact": "Query manipulation via comments",         "recommendation": "Strip or sanitize comment markers",         "regex": r"(?:--|\/\*)[^\n\r]*\$_(?:GET|POST|REQUEST)"},
    {"name": "Conditional tautology injection",   "severity": 3, "message": "Boolean condition from user input in SQL",         "impact": "Blind‑based SQL injection",               "recommendation": "Avoid inline boolean expressions",         "regex": r"\b(AND|OR)\s+[\w'\"\.]+\s*=\s*[\w'\"\.]*\$_(?:GET|POST|REQUEST)"},
    {"name": "INLINE TABLE injection",            "severity": 3, "message": "User input in inline VALUES() table",               "impact": "Data insertion SQL injection",           "recommendation": "Use parameterized VALUES clauses",         "regex": r"\bVALUES\s*\([\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?\)"},
    {"name": "Comment‑terminator injection",      "severity": 2, "message": "User input ending statement with -- or #",         "impact": "Trailing‑comment SQL injection",          "recommendation": "Remove comment markers from input",        "regex": r"\$_(?:GET|POST|REQUEST)[^;]*\s*(?:--|#)"},
    {"name": "MS SQL xp_cmdshell injection",      "severity": 3, "message": "User input passed to xp_cmdshell",                  "impact": "OS command execution via SQL",           "recommendation": "Disable xp_cmdshell; parameterize queries", "regex": r"\bxp_cmdshell\b[^\n\r]*\$_(?:GET|POST|REQUEST)"},
    {"name":"Boolean tautology injection","severity":3,"message":"Boolean condition always true via user input","impact":"Bypass auth/data exfiltration","recommendation":"Use parameterized queries","regex":r"\b(?:OR|AND)\b\s*['\"]?[\w\d]+['\"]?\s*=\s*['\"]?[\w\d]+['\"]?"},
    {"name":"UNION SELECT injection","severity":3,"message":"UNION SELECT used with user input","impact":"Data exfiltration via UNION","recommendation":"Disallow UNION; use prepared statements","regex":r"\bUNION\b\s*SELECT\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"Stacked query injection","severity":3,"message":"Multiple SQL statements via semicolon","impact":"Execute arbitrary commands","recommendation":"Disable multi‑statement execution","regex":r";\s(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\b"},
    {"name":"Time‑based blind injection","severity":3,"message":"SLEEP() or BENCHMARK() with user input","impact":"Blind injection via delay","recommendation":"Parameterize numeric inputs","regex":r"\b(?:SLEEP|BENCHMARK)\s*\(\s*\d+\s*\)"},
    {"name":"Hex constant injection","severity":3,"message":"User‑supplied hex literal in query","impact":"Obfuscated injection","recommendation":"Validate numeric formats; bind params","regex":r"\b0x[0-9A-F]+\b"},
    {"name":"Subquery injection","severity":3,"message":"User input inside a sub‑SELECT","impact":"Nested injection risk","recommendation":"Avoid dynamic subqueries; bind params","regex":r"\(\s*SELECT\b[\s\S]*?\$_(?:GET|POST|REQUEST)[\s\S]*?\)"},
    {"name":"IN clause injection","severity":3,"message":"User input in IN(...) list","impact":"Filtering bypass or enumeration","recommendation":"Parse & whitelist list values","regex":r"\bIN\s*\(\s*.*\$_(?:GET|POST|REQUEST)[^)]*\)"},
    {"name":"LIKE wildcard injection","severity":3,"message":"Wildcard pattern from user input","impact":"Pattern‑based data leakage","recommendation":"Escape % and _ or bind values","regex":r"\bLIKE\b\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name":"ORDER BY injection","severity":2,"message":"User input in ORDER BY clause","impact":"Manipulate sort order","recommendation":"Whitelist sortable columns","regex":r"\bORDER\s+BY\b\s*[\w,\s]*\$_(?:GET|POST|REQUEST)"},
    {"name":"LIMIT clause injection","severity":2,"message":"User input in LIMIT clause","impact":"Row‑count manipulation; DoS risk","recommendation":"Validate numeric bounds","regex":r"\bLIMIT\b\s*\d+\s*(?:,\s*\d+)?"},
    {"name":"GROUP BY injection","severity":2,"message":"User input in GROUP BY clause","impact":"Aggregation manipulation","recommendation":"Whitelist grouping columns","regex":r"\bGROUP\s+BY\b\s*[\w,\s]*\$_(?:GET|POST|REQUEST)"},
    {"name":"HAVING clause injection","severity":2,"message":"User input in HAVING clause","impact":"Filtered aggregation injection","recommendation":"Bind parameters explicitly","regex":r"\bHAVING\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"Comment‑truncation injection","severity":2,"message":"SQL comment to truncate rest of query","impact":"Terminate original query and append payload","recommendation":"Strip or sanitize comment markers","regex":r"(?m)(--|#|\/\*)[^\r\n]*"},
    {"name":"CASE/IF injection","severity":3,"message":"CASE or IF construct with user input","impact":"Logic‑based injection","recommendation":"Parameterize control expressions","regex":r"\b(?:CASE|IF)\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"JSON_EXTRACT injection","severity":2,"message":"JSON_EXTRACT/JSON_SEARCH with user input","impact":"Hybrid JSON/SQL injection","recommendation":"Bind JSON paths & values","regex":r"\bJSON_(?:EXTRACT|SEARCH)\s*\([\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"XML function injection","severity":2,"message":"UPDATEXML/EXTRACTVALUE with user data","impact":"Error‑based injection via XML functions","recommendation":"Parameterize XML function args","regex":r"\b(?:UPDATEXML|EXTRACTVALUE)\s*\([\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"Bitwise operator injection","severity":2,"message":"User input used with &|^ operators","impact":"Obscure boolean injection","recommendation":"Validate & bind numeric inputs","regex":r"\$_(?:GET|POST|REQUEST)\s*[&|^]\s*[\w\d]+"},
    {"name":"xp_cmdshell injection","severity":3,"message":"User input passed to xp_cmdshell","impact":"OS command execution via SQL","recommendation":"Disable xp_cmdshell; use safe APIs","regex":r"\bxp_cmdshell\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"SELECT_from injection","severity":3,"message":"User input in SELECT…FROM","impact":"Data exfiltration","recommendation":"Use prepared statements","regex":r"\bSELECT\b[\s\S]*?\$_(?:GET|POST|REQUEST)[\s\S]*?\bFROM\b"},
    {"name":"INSERT_INTO injection","severity":3,"message":"User input in INSERT INTO","impact":"Data manipulation","recommendation":"Use prepared INSERT","regex":r"\bINSERT\s+INTO\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"UPDATE_SET injection","severity":3,"message":"User input in UPDATE…SET","impact":"Data manipulation","recommendation":"Use prepared UPDATE","regex":r"\bUPDATE\b[\s\S]*?\bSET\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"DELETE_FROM injection","severity":3,"message":"User input in DELETE FROM","impact":"Data deletion","recommendation":"Use prepared DELETE","regex":r"\bDELETE\s+FROM\b[\s\S]*?\$_(?:GET|POST|REQUEST)"},
    {"name":"sp_executesql injection","severity":3,"message":"sp_executesql() called with user input","impact":"T‑SQL injection via dynamic SQL","recommendation":"Use parameterized sp_executesql with placeholders","regex":r"\bsp_executesql\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::raw() injection","severity":3,"message":"DB::raw() invoked with user data","impact":"SQL injection via unescaped raw expression","recommendation":"Use query builder bindings or parameterized queries","regex":r"DB::raw\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CodeIgniter query() injection","severity":3,"message":"$this->db->query() with user input","impact":"SQL injection via direct CI query","recommendation":"Use query bindings (`?` or `:key`)","regex":r"\$this->db->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"WordPress $wpdb->query() injection","severity":3,"message":"$wpdb->query() called with user data","impact":"SQL injection in WordPress database access","recommendation":"Use `$wpdb->prepare()` with placeholders","regex":r"\$wpdb->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"MySQLi real_query() injection","severity":3,"message":"real_query() invoked with user input","impact":"SQL injection via mysqli real_query","recommendation":"Use `prepare()` + `execute()` instead","regex":r"->real_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQLite exec() injection","severity":3,"message":"exec() run on user‑supplied SQL","impact":"SQL injection in SQLite","recommendation":"Use prepared statements or parameter binding","regex":r"(?:SQLite3|PDOSQLite)->exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"EXECUTE IMMEDIATE injection","severity":3,"message":"EXECUTE IMMEDIATE with user‑controlled string","impact":"Dynamic SQL injection in PL/SQL/T‑SQL","recommendation":"Use bind variables or parameterized calls","regex":r"\bEXECUTE\s+IMMEDIATE\s+['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Doctrine createQuery() injection","severity":3,"message":"createQuery() built from user input","impact":"DQL injection via untrusted query string","recommendation":"Use parameter placeholders and bind values","regex":r"->createQuery\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Propel createQuery() injection","severity":3,"message":"Propel->createQuery() with user data","impact":"ORM‑level SQL injection","recommendation":"Use parameter binding or query criteria APIs","regex":r"->createQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Raw PDO prepare misuse","severity":3,"message":"PDO->prepare() contains embedded user input","impact":"SQL injection despite using prepare()","recommendation":"Use `?` or named placeholders instead of embedding variables","regex":r"\bPDO->prepare\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)[^\"']*['\"]"},
    {"name":"Stored procedure CALL injection","severity":3,"message":"CALL proc(...) with user input","impact":"SQL injection via stored procedure arguments","recommendation":"Validate or bind all procedure parameters","regex":r"\bCALL\s+\w+\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Bulk ORM method injection","severity":3,"message":"bulkCreate/updateMany with user data","impact":"SQL injection via mass assignment","recommendation":"Whitelist fields and bind values","regex":r"\b(?:bulkCreate|batchInsert|updateMany)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Drupal db_query() injection","severity":3,"message":"db_query() with user input","impact":"SQLi via Drupal DB API","recommendation":"Use placeholders or db_select() with conditions","regex":r"\bdb_query\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Drupal db_select()->execute() injection","severity":3,"message":"db_select()->execute() with unsanitized parameters","impact":"SQLi via dynamic selection","recommendation":"Use addFieldCondition or placeholders","regex":r"db_select\s*\(\s*.*\)->execute\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"Joomla setQuery() injection","severity":3,"message":"$db->setQuery() called with user data","impact":"SQLi via Joomla DB","recommendation":"Use bindPlaceholder on the query object","regex":r"\$db->setQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Magento getConnection()->query() injection","severity":3,"message":"Raw query via Magento connection","impact":"SQLi in Magento","recommendation":"Use select() or bound params","regex":r"getConnection\(\)\s*->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::statement() injection","severity":3,"message":"DB::statement() with user input","impact":"SQLi in Laravel","recommendation":"Use parameter binding or query builder","regex":r"DB::statement\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::select() injection","severity":3,"message":"DB::select() with unsanitized SQL","impact":"SQLi in Laravel","recommendation":"Use parameter binding","regex":r"DB::select\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel whereRaw() injection","severity":3,"message":"->whereRaw() with user input","impact":"SQLi via raw where clause","recommendation":"Use bindings or where()","regex":r"\bwhereRaw\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel orderByRaw() injection","severity":2,"message":"->orderByRaw() with user input","impact":"SQLi via raw order by clause","recommendation":"Whitelist sortable columns","regex":r"\borderByRaw\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Yii createCommand() injection","severity":3,"message":"createCommand() built from user data","impact":"SQLi via Yii DB","recommendation":"Use params array for binding","regex":r"\bcreateCommand\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Yii execute() injection","severity":3,"message":"execute() on user‑built SQL","impact":"SQLi via Yii DB","recommendation":"Use bindValue or bindParam","regex":r"->execute\s*\(\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"CakePHP query() injection","severity":3,"message":"->query() with user input","impact":"SQLi via CakePHP DB","recommendation":"Use `->execute()` with prepared statements","regex":r"->query\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Symfony DBAL executeQuery() injection","severity":3,"message":"executeQuery() with unsanitized SQL","impact":"SQLi via Symfony DBAL","recommendation":"Use parameter placeholders","regex":r"->executeQuery\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Propel deleteAll() injection","severity":3,"message":"deleteAll() with dynamic condition","impact":"SQLi via Propel","recommendation":"Use delete()->where() with bindings","regex":r"deleteAll\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"ColdFusion cfqueryparam missing","severity":3,"message":"<cfquery> without cfqueryparam","impact":"SQLi in ColdFusion","recommendation":"Always wrap user input in <cfqueryparam>","regex":r"<cfquery\b[^>]*>[\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?<\/cfquery>"},
    {"name":"WordPress $wpdb->query() injection","severity":3,"message":"Raw $wpdb->query() with user input","impact":"SQLi in WP","recommendation":"Use $wpdb->prepare() with placeholders","regex":r"\$wpdb->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"WordPress $wpdb->prepare() misuse","severity":3,"message":"Improper $wpdb->prepare() string concatenation","impact":"SQLi despite prepare","recommendation":"Pass variables as separate args to prepare","regex":r"\$wpdb->prepare\s*\(\s*['\"].*\.\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"WordPress $wpdb->get_(row|results) injection","severity":3,"message":"$wpdb->get_row/get_results with unsanitized SQL","impact":"SQLi in WP","recommendation":"Use prepare()","regex":r"\$wpdb->get_(?:row|results)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CodeIgniter $this->db->query() injection","severity":3,"message":"CI db->query() with user input","impact":"SQLi in CI","recommendation":"Use query bindings","regex":r"\$this->db->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CodeIgniter $this->db->where() injection","severity":3,"message":"CI db->where() with raw input","impact":"SQLi in CI","recommendation":"Use bindings in second param","regex":r"\$this->db->where\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Zend Framework fetchAll() injection","severity":3,"message":"Zend DB->fetchAll() with user data","impact":"SQLi in ZF","recommendation":"Use parameter placeholders","regex":r"\$db->fetchAll\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Yii ActiveRecord findBySql() injection","severity":3,"message":"Yii->findBySql() with raw WHERE","impact":"SQLi in Yii AR","recommendation":"Use parameter binding","regex":r"findBySql\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Symfony raw DQL in createQuery()","severity":3,"message":"Unbound DQL in Symfony repository","impact":"SQLi via DQL","recommendation":"Use setParameter()","regex":r"createQuery\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"TYPO3 sql_query() injection","severity":3,"message":"TYPO3_DB->sql_query() with user input","impact":"SQLi in TYPO3","recommendation":"Use prepared statements","regex":r"TYPO3_DB->sql_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Magento fetchAll()/query() injection","severity":3,"message":"Raw query via Magento connection","impact":"SQLi in Magento","recommendation":"Use bind() on select object","regex":r"(?:fetchAll|query)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::statement() injection","severity":3,"message":"DB::statement() with user input","impact":"SQLi in Laravel","recommendation":"Use parameter binding or query builder","regex":r"DB::statement\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel whereRaw()/orderByRaw() injection","severity":3,"message":"->whereRaw()/orderByRaw() with user input","impact":"SQLi via raw clauses","recommendation":"Use bindings or whitelist columns","regex":r"\b(?:whereRaw|orderByRaw)\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Doctrine DQL injection via createQuery()","severity":3,"message":"DQL built from user input","impact":"SQLi via Doctrine","recommendation":"Use setParameter()","regex":r"createQuery\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Propel deleteAll() injection","severity":3,"message":"deleteAll() with dynamic condition","impact":"SQLi via Propel","recommendation":"Use delete()->where() with bindings","regex":r"deleteAll\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"ColdFusion cfquery without cfqueryparam","severity":3,"message":"<cfquery> missing cfqueryparam","impact":"SQLi in ColdFusion","recommendation":"Wrap all user inputs in <cfqueryparam>","regex":r"<cfquery\b[^>]*>[\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?<\/cfquery>"},
    {"name":"ODBC exec() injection","severity":3,"message":"odbc_exec() with user input","impact":"SQLi via ODBC","recommendation":"Use parameterized queries","regex":r"\bodbc_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Sybase sybase_query() injection","severity":3,"message":"sybase_query() with user input","impact":"SQLi via Sybase","recommendation":"Use parameter placeholders","regex":r"\bsybase_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Informix ifx_query() injection","severity":3,"message":"ifx_query() with user input","impact":"SQLi via Informix","recommendation":"Use parameterized queries","regex":r"\bifx_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"DB2 db2_exec() injection","severity":3,"message":"db2_exec() with user input","impact":"SQLi via DB2","recommendation":"Use parameter binding","regex":r"\bdb2_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Interbase ibase_query() injection","severity":3,"message":"ibase_query() with user input","impact":"SQLi via Interbase","recommendation":"Use parameterized queries","regex":r"\bibase_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"MSSQL mysql-like mssql_query() injection","severity":3,"message":"mssql_query() with user input","impact":"SQLi via MS‑SQL","recommendation":"Use parameter placeholders","regex":r"\bmssql_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Server sp_executesql injection","severity":3,"message":"sp_executesql() with user SQL","impact":"SQLi via dynamic SQL","recommendation":"Use parameter list in sp_executesql","regex":r"\bsp_executesql\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Server OPENROWSET injection","severity":3,"message":"OPENROWSET() with user input","impact":"SQLi via ad‑hoc distributed queries","recommendation":"Avoid dynamic OPENROWSET; bind inputs","regex":r"\bOPENROWSET\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Generic CALL proc() injection","severity":3,"message":"CALL procedureName(...) with user input","impact":"SQLi via stored proc","recommendation":"Use parameter binding","regex":r"\bCALL\b[\s\S]*\$_(?:GET|POST|REQUEST)"},
    {"name":"ODBC exec() injection","severity":3,"message":"odbc_exec() with user input","impact":"SQLi via ODBC","recommendation":"Use parameterized queries","regex":r"\bodbc_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Sybase query() injection","severity":3,"message":"sybase_query() with user input","impact":"SQLi via Sybase","recommendation":"Use parameter placeholders","regex":r"\bsybase_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Informix ifx_query() injection","severity":3,"message":"ifx_query() with user input","impact":"SQLi via Informix","recommendation":"Use parameterized queries","regex":r"\bifx_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"DB2 db2_exec() injection","severity":3,"message":"db2_exec() with user input","impact":"SQLi via DB2","recommendation":"Use parameter binding","regex":r"\bdb2_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Interbase ibase_query() injection","severity":3,"message":"ibase_query() with user input","impact":"SQLi via Interbase","recommendation":"Use parameterized queries","regex":r"\bibase_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"MSSQL mssql_query() injection","severity":3,"message":"mssql_query() with user input","impact":"SQLi via MS‑SQL","recommendation":"Use parameter placeholders","regex":r"\bmssql_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQL Server sp_executesql injection","severity":3,"message":"sp_executesql() with dynamic SQL","impact":"SQLi via dynamic SQL","recommendation":"Use parameter list with sp_executesql","regex":r"\bsp_executesql\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQLite sqlite_query() injection","severity":3,"message":"sqlite_query() with user input","impact":"SQLi via SQLite","recommendation":"Use sqlite_prepare() and sqlite_bind","regex":r"\bsqlite_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"SQLite sqlite_exec() injection","severity":3,"message":"sqlite_exec() with user input","impact":"SQLi via SQLite","recommendation":"Use sqlite_prepare() and sqlite_bind","regex":r"\bsqlite_exec\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"WP $wpdb->query() injection","severity":3,"message":"Raw $wpdb->query() with user input","impact":"SQLi in WP","recommendation":"Use $wpdb->prepare()","regex":r"\$wpdb->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"WP prepare() misuse","severity":3,"message":"Concatenated SQL inside $wpdb->prepare()","impact":"SQLi despite prepare","recommendation":"Pass vars as separate args","regex":r"\$wpdb->prepare\s*\(\s*['\"].*\.\s*\$_(?:GET|POST|REQUEST)"},
    {"name":"WP get_(?:var|row|results) injection","severity":3,"message":"$wpdb->get_*() with unsanitized SQL","impact":"SQLi in WP","recommendation":"Use $wpdb->prepare()","regex":r"\$wpdb->get_(?:var|row|results)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CI $this->db->query() injection","severity":3,"message":"db->query() with user input","impact":"SQLi in CI","recommendation":"Use query bindings","regex":r"\$this->db->query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CI $this->db->where() injection","severity":3,"message":"db->where() with raw input","impact":"SQLi in CI","recommendation":"Use bindings in second param","regex":r"\$this->db->where\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CI $this->db->like() injection","severity":3,"message":"db->like() with raw input","impact":"SQLi in CI","recommendation":"Use escape_like_str()","regex":r"\$this->db->like\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::statement() injection","severity":3,"message":"DB::statement() with user input","impact":"SQLi in Laravel","recommendation":"Use bindings or query builder","regex":r"DB::statement\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel whereRaw()/orderByRaw() injection","severity":3,"message":"whereRaw()/orderByRaw() with user input","impact":"SQLi via raw clauses","recommendation":"Use bindings or whitelist col names","regex":r"\b(?:whereRaw|orderByRaw)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Laravel DB::raw() injection","severity":3,"message":"DB::raw() with user input","impact":"SQLi via raw expression","recommendation":"Avoid DB::raw() or bind values","regex":r"DB::raw\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Symfony executeQuery() injection","severity":3,"message":"Connection->executeQuery() with raw SQL","impact":"SQLi in Symfony","recommendation":"Use ? or named parameters","regex":r"->executeQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Symfony executeUpdate() injection","severity":3,"message":"Connection->executeUpdate() with raw SQL","impact":"SQLi in Symfony","recommendation":"Use ? or named parameters","regex":r"->executeUpdate\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Doctrine NativeQuery injection","severity":3,"message":"NativeQuery with concatenated SQL","impact":"SQLi in Doctrine","recommendation":"Use query parameters","regex":r"NativeQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Doctrine DQL createQuery() injection","severity":3,"message":"Unbound DQL in createQuery()","impact":"SQLi via DQL","recommendation":"Use setParameter()","regex":r"createQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Yii findBySql() injection","severity":3,"message":"ActiveRecord findBySql() with user data","impact":"SQLi in Yii AR","recommendation":"Pass parameters to findBySql()","regex":r"findBySql\s*\(\s*['\"].*\$_(?:GET|POST|REQUEST)"},
    {"name":"Yii Connection->createCommand() injection","severity":3,"message":"createCommand() with raw SQL","impact":"SQLi in Yii","recommendation":"Use bindValue()/bindParam()","regex":r"createCommand\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Joomla $db->setQuery() injection","severity":3,"message":"Joomla setQuery() with user input","impact":"SQLi in Joomla","recommendation":"Use $db->quote() or prepared statements","regex":r"\$db->setQuery\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Drupal db_query() injection","severity":3,"message":"db_query() with user input","impact":"SQLi in Drupal","recommendation":"Use placeholders in db_query()","regex":r"\bdb_query\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Drupal db_select() injection","severity":3,"message":"db_select() with dynamic conditions","impact":"SQLi in Drupal","recommendation":"Use conditions() with args","regex":r"\bdb_select\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"CF <cfquery> without cfqueryparam","severity":3,"message":"<cfquery> missing cfqueryparam","impact":"SQLi in CF","recommendation":"Wrap inputs in <cfqueryparam>","regex":r"<cfquery\b[^>]*>[\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?<\/cfquery>"},
    {"name":"innerHTML assignment","severity":3,"message":"Unescaped user input assigned to innerHTML","impact":"DOM‑based XSS","recommendation":"Sanitize or avoid innerHTML","regex":r"\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"document.write injection","severity":3,"message":"document.write() with user input","impact":"DOM‑based XSS","recommendation":"Avoid document.write() with untrusted data","regex":r"document\.write(?:ln)?\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"jQuery html() injection","severity":3,"message":"jQuery html() with user input","impact":"DOM‑based XSS","recommendation":"Escape or use text() instead of html()","regex":r"\.html\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"jQuery append/prepend injection","severity":3,"message":"jQuery append()/prepend() with user input","impact":"DOM‑based XSS","recommendation":"Escape HTML before inserting","regex":r"\.(?:append|prepend)\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"inline event‑handler attr injection","severity":3,"message":"Inline on* attribute with user input","impact":"XSS via event handlers","recommendation":"Use addEventListener; avoid inline handlers","regex":r"<\w+\s+[^>]*on\w+\s*=\s*['\"].*\$_(?:GET|POST|REQUEST).*['\"]"},
    {"name":"script tag injection","severity":3,"message":"<script> block with user input","impact":"Direct script injection","recommendation":"Sanitize or remove dynamic script content","regex":r"<script\b[^>]*>[\s\S]*\$_(?:GET|POST|REQUEST)[\s\S]*?<\/script>"},
    {"name":"Mustache/Twig/Blade raw injection","severity":3,"message":"Unescaped template raw block","impact":"Server/client template XSS","recommendation":"Use escaped interpolation","regex":r"\{\{\{\s*.*\$_(?:GET|POST|REQUEST).*?\}\}\}|\{!!\s*.*\$_(?:GET|POST|REQUEST)\s*!!\}|\{\%\s*raw\s*\%\}"},
    {"name":"Twig raw filter misuse","severity":3,"message":"Twig `|raw` on user data","impact":"Server‑side template XSS","recommendation":"Remove `raw` filter; escape all input","regex":r"\|\s*raw\s*}}"},
    {"name":"React dangerouslySetInnerHTML","severity":3,"message":"React dangerouslySetInnerHTML with user data","impact":"React‑based XSS","recommendation":"Avoid dangerouslySetInnerHTML","regex":r"dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"Angular innerHTML binding","severity":3,"message":"Angular [innerHTML] bound to user input","impact":"Angular XSS","recommendation":"Use [textContent] or sanitizer","regex":r"\[innerHTML\]\s*=\s*\".*\$_(?:GET|POST|REQUEST).*\""},
    {"name":"location.href/assign injection","severity":3,"message":"Untrusted input assigned to window.location","impact":"DOM‑based XSS","recommendation":"Validate or sanitize URLs","regex":r"window\.location(?:\.href|\.assign|\.replace)\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"document.cookie injection","severity":3,"message":"User data written into document.cookie","impact":"Cookie poisoning & XSS","recommendation":"Sanitize cookie values","regex":r"document\.cookie\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"window.open injection","severity":3,"message":"window.open() called with user URL","impact":"DOM‑based XSS / phishing","recommendation":"Validate URLs before opening","regex":r"window\.open\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"new Function() injection","severity":3,"message":"Dynamic function created from user input","impact":"Arbitrary JS execution","recommendation":"Avoid new Function; use static code","regex":r"new\s+Function\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"RegExp constructor injection","severity":2,"message":"RegExp built from untrusted input","impact":"Regex‑based XSS or DoS","recommendation":"Escape or validate regex patterns","regex":r"new\s+RegExp\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"anchor href injection","severity":2,"message":"<a href=> contains user data","impact":"JavaScript URI XSS / phishing","recommendation":"Whitelist or encode URLs","regex":r"<a\b[^>]*\bhref\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name":"<img onerror> injection","severity":3,"message":"Untrusted input in onerror handler","impact":"DOM‑based XSS","recommendation":"Remove inline handlers; use safe listeners","regex":r"<img\b[^>]*\bonerror\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name":"<body onload> injection","severity":2,"message":"User data in body onload","impact":"Auto‑executed XSS","recommendation":"Avoid inline onload; bind safely","regex":r"<body\b[^>]*\bonload\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},
    {"name":"style.cssText injection","severity":2,"message":"Untrusted data assigned to cssText","impact":"CSS‑based XSS","recommendation":"Sanitize CSS or avoid cssText","regex":r"style\.cssText\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"createElement(src) injection","severity":3,"message":"Dynamic element.src set from user input","impact":"DOM‑based XSS / content injection","recommendation":"Validate src values","regex":r"document\.createElement\s*\(\s*['\"](?:script|img|iframe)['\"]\s*\)\s*;?\s*.*\.src\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"eval() on template strings","severity":3,"message":"eval() used on template with user data","impact":"Arbitrary JS execution","recommendation":"Avoid eval; use safe parsers","regex":r"eval\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"innerText misuse","severity":1,"message":"innerText used for HTML insertion","impact":"Potential XSS if fallback to innerHTML","recommendation":"Use textContent or escape","regex":r"\.innerText\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"document.write injection","severity":3,"message":"document.write() with user input","impact":"DOM‑based XSS","recommendation":"Avoid document.write; use safe text insertion","regex":r"document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"document.writeln injection","severity":3,"message":"document.writeln() with user input","impact":"DOM‑based XSS","recommendation":"Avoid writeln; use safe text insertion","regex":r"document\.writeln\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"innerHTML assignment","severity":3,"message":"Untrusted data assigned to innerHTML","impact":"DOM‑based XSS","recommendation":"Use textContent or escape before assignment","regex":r"\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"insertAdjacentHTML injection","severity":3,"message":"insertAdjacentHTML() called with user data","impact":"DOM‑based XSS","recommendation":"Validate or sanitize HTML fragments","regex":r"insertAdjacentHTML\s*\(\s*['\"][^'\"]+['\"]\s*,\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"outerHTML assignment","severity":3,"message":"User data assigned to outerHTML","impact":"DOM‑based XSS","recommendation":"Sanitize or avoid outerHTML assignment","regex":r"\.outerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"jQuery html() injection","severity":3,"message":".html() called with user input","impact":"DOM‑based XSS","recommendation":"Escape HTML or use text()","regex":r"\.html\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"jQuery append() injection","severity":3,"message":".append() called with user input","impact":"DOM‑based XSS","recommendation":"Escape HTML before appending","regex":r"\.append\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"jQuery replaceWith() injection","severity":3,"message":".replaceWith() with user input","impact":"DOM‑based XSS","recommendation":"Escape HTML before replacing","regex":r"\.replaceWith\s*\(\s*.*\$_(?:GET|POST|REQUEST)"},
    {"name":"iframe srcdoc injection","severity":3,"message":"<iframe srcdoc> with user data","impact":"DOM‑based XSS","recommendation":"Sanitize srcdoc content","regex":r"<iframe\b[^>]*\bsrcdoc\s*=\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)[^'\"]*['\"]"},

]

RAW_VULN_PATTERNS = [
    {"name": "Use of eval()", "severity": 3, "message": "Eval on user input", "impact": "Arbitrary code execution", "recommendation": "Remove eval() usage", "regex": r"\beval\s*\("},
    {"name": "Obfuscated eval(b64)", "severity": 3, "message": "eval(base64_decode())", "impact": "RCE via encoded payload", "recommendation": "Disable obfuscation", "regex": r"eval\s*\(\s*base64_decode"},
    {"name": "Shell execution", "severity": 3, "message": "system/exec functions", "impact": "Command injection", "recommendation": "Sanitize inputs; avoid shell calls", "regex": r"\b(system|exec|shell_exec|passthru)\s*\("},  
]
SANITIZER_PATTERNS = [
    re.compile(r"htmlspecialchars\s*\(", re.IGNORECASE),
    re.compile(r"htmlentities\s*\(",     re.IGNORECASE),
    re.compile(r"strip_tags\s*\(",       re.IGNORECASE),
    re.compile(r"filter_var\s*\(\s*\$?[A-Za-z_]\w*\s*,\s*FILTER_SANITIZE_[A-Z_]+\s*\)", re.IGNORECASE),
    re.compile(r"filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,\s*['\"][A-Za-z0-9_]+['\"]\s*,\s*FILTER_SANITIZE_[A-Z_]+\s*\)", re.IGNORECASE),
    re.compile(r"filter_input_array\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,", re.IGNORECASE),
    re.compile(r"urlencode\s*\(",    re.IGNORECASE),
    re.compile(r"rawurlencode\s*\(", re.IGNORECASE),
    re.compile(r"addslashes\s*\(",                    re.IGNORECASE),
    re.compile(r"mysqli_real_escape_string\s*\(",     re.IGNORECASE),
    re.compile(r"\$pdo->quote\s*\(",                  re.IGNORECASE),
    re.compile(r"\$stmt->bindParam\s*\(",             re.IGNORECASE),
    re.compile(r"\$stmt->bindValue\s*\(",             re.IGNORECASE),
    re.compile(r"escapeshellarg\s*\(", re.IGNORECASE),
    re.compile(r"escapeshellcmd\s*\(", re.IGNORECASE),
    re.compile(r"realpath\s*\(", re.IGNORECASE),
    re.compile(r"basename\s*\(", re.IGNORECASE),
]

TAINT_SOURCE_PATTERNS = [
    re.compile(r"\$([A-Za-z_]\w*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|SESSION|FILES|SERVER|ENV)\[", re.IGNORECASE),
    re.compile(r"\$([A-Za-z_]\w*)\s*=\s*filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,", re.IGNORECASE),
    re.compile(r"\$([A-Za-z_]\w*)\s*=\s*filter_input_array\s*\(\s*INPUT_(?:GET|POST|COOKIE)\s*,", re.IGNORECASE),
    re.compile(r"\$([A-Za-z_]\w*)\s*=\s*file_get_contents\s*\(\s*['\"]php://input['\"]\s*\)", re.IGNORECASE),
    re.compile(r"\$([A-Za-z_]\w*)\s*=\s*fopen\s*\(\s*['\"]php://input['\"]\s*,", re.IGNORECASE),
]

# -------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------
@dataclass
class Finding:
    file: str
    lineno: int
    vuln: str
    severity: int
    message: str
    snippet: str

@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)

    def summary(self):
        counts = {}
        for f in self.findings:
            counts[f.vuln] = counts.get(f.vuln, 0) + 1
        return counts

    def to_json(self):
        return json.dumps([f.__dict__ for f in self.findings], indent=2)

# -------------------------------------------------------------------
# Scanner implementation
# -------------------------------------------------------------------
class PhpVulnScanner:
    def __init__(self, raw_patterns, sanitizers, threads=4, min_sev=1):
        self.patterns = []
        for p in raw_patterns:
            compiled = re.compile(p['regex'], re.IGNORECASE)
            self.patterns.append({
                'name': p['name'],
                'regex': compiled,
                'message': p['message'],
                'severity': p['severity'],
            })
        self.sanitizers = sanitizers
        self.threads = threads
        self.min_sev = min_sev

    def collect_files(self, root):
        if os.path.isdir(root):
            for dp, _, files in os.walk(root):
                for fn in files:
                    if fn.lower().endswith('.php'):
                        yield os.path.join(dp, fn)
        else:
            yield root

    def scan_file(self, filepath):
        try:
            code = Path(filepath).read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []

        findings = []
        tainted_vars = set()
        for pat in TAINT_SOURCE_PATTERNS:
            for m in pat.finditer(code):
                tainted_vars.add(m.group(1))

        for rule in self.patterns:
            if rule['severity'] < self.min_sev:
                continue
            regex = rule['regex']
            for m in regex.finditer(code):
                line_no = code.count('\n', 0, m.start()) + 1
                lines = code.splitlines()
                if line_no - 1 < len(lines):
                    line = lines[line_no - 1].strip()
                else:
                    continue
                if any(s.search(line) for s in self.sanitizers):
                    continue
                snippet = m.group(0)
                if not tainted_vars or any(var in snippet for var in tainted_vars):
                    findings.append(Finding(
                        file=filepath,
                        lineno=line_no,
                        vuln=rule['name'],
                        severity=rule['severity'],
                        message=rule['message'],
                        snippet=line
                    ))
        return findings

    def run(self, target):
        report = ScanReport()
        files = list(self.collect_files(target))
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_file, f): f for f in files}
            for fut in as_completed(futures):
                report.findings.extend(fut.result())
        return report

# -------------------------------------------------------------------
# CLI & entrypoint
# -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='PHP Vulnerability Scanner (fixed)')
    parser.add_argument('target', help='PHP file or directory')
    parser.add_argument('--min-sev', type=int, choices=(1,2,3), default=1)
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.min_sev == 1 else logging.INFO)

    scanner = PhpVulnScanner(RAW_VULN_PATTERNS, SANITIZER_PATTERNS,
                             threads=args.threads, min_sev=args.min_sev)
    report = scanner.run(args.target)

    if args.json:
        print(report.to_json())
    else:
        for f in report.findings:
            print(f"{f.file}:{f.lineno}  {f.vuln} (sev={f.severity})\n    → {f.message}\n    Code: {f.snippet}\n")
        print("Summary:")
        for vuln, cnt in report.summary().items():
            print(f"  - {vuln}: {cnt}")

if __name__ == '__main__':
    main()
