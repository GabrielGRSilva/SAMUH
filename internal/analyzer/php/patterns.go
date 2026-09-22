package php

import (
	"regexp"

	"samuh/internal/rules"
)

type pattern struct {
	Regex *regexp.Regexp
	Rule  rules.Rule
}

var vulnerabilityPatterns = []pattern{
	// A01 - Broken Access Control
	{
		Regex: regexp.MustCompile(`(?i)(?:if\s*\(\s*\$_(?:SESSION|COOKIE|GET|POST|REQUEST)\[['"](?:admin|role|is_admin|group)['"]\]\s*(?:==|===|!=|!==)\s*['"]?(?:admin|root|true|1)['"]?\s*\))`),
		Rule: rules.Rule{
			ID:          "PHP-A01-001",
			Title:       "Missing or Weak Authorization Check",
			Description: "Directly checking user roles from input or unverified session data can lead to privilege escalation.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-285",
			Remediation: "Implement robust authorization checks using a centralized access control library.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:\$id\s*=\s*\$_(?:GET|POST|REQUEST)\[['"]id['"]\]\s*;\s*\$sql\s*=\s*['"]SELECT.*?WHERE id\s*=\s*\$id['"])`),
		Rule: rules.Rule{
			ID:          "PHP-A01-002",
			Title:       "Direct Object Reference (IDOR)",
			Description: "Directly accessing database records by user-supplied ID without ownership validation.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-639",
			Remediation: "Verify the authenticated user has permission to access the requested object ID.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\)`),
		Rule: rules.Rule{
			ID:          "PHP-A01-003",
			Title:       "CORS Wildcard Configuration",
			Description: "Setting Access-Control-Allow-Origin to '*' exposes the API to requests from any domain.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-942",
			Remediation: "Specify an explicit, restrictive list of allowed origin domains.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:file_get_contents|fopen|readfile)\s*\(\s*.*?\$_(?:GET|POST|REQUEST)\[.*?\]\s*.*?\)`),
		Rule: rules.Rule{
			ID:          "PHP-A01-004",
			Title:       "Directory Traversal / LFI via File Operations",
			Description: "Using user input directly in file operations can allow reading arbitrary files.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-22",
			Remediation: "Use realpath() and verify the resolved path is within the intended base directory.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)\[.*?\]\s*\)|file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)\[.*?\]\s*\))`),
		Rule: rules.Rule{
			ID:          "PHP-A01-005",
			Title:       "Server-Side Request Forgery (SSRF)",
			Description: "Passing user input to URL fetching functions can cause the server to make arbitrary requests.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-918",
			Remediation: "Validate URLs against a strict allowlist of domains/IPs. Do not allow internal IP access.",
		},
	},

	// A02 - Security Misconfiguration
	{
		Regex: regexp.MustCompile(`(?i)ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"](?:1|On|true)['"]\s*\)`),
		Rule: rules.Rule{
			ID:          "PHP-A02-001",
			Title:       "Display Errors Enabled",
			Description: "Enabling display_errors exposes sensitive internal application details to users.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-209",
			Remediation: "Set display_errors to Off in production. Log errors instead.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)error_reporting\s*\(\s*(?:E_ALL|E_ALL\s*\|\s*E_STRICT)\s*\)`),
		Rule: rules.Rule{
			ID:          "PHP-A02-002",
			Title:       "Verbose Error Reporting",
			Description: "Setting error_reporting to E_ALL in code might override environment configurations, exposing too much info.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-209",
			Remediation: "Ensure verbose error reporting is disabled in production.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:define|const)\s*\(?['"](?:DB_PASS|DB_PASSWORD|PASSWORD|SECRET)['"]\s*,\s*['"](?:root|admin|password|12345)['"]\)?`),
		Rule: rules.Rule{
			ID:          "PHP-A02-003",
			Title:       "Default or Weak Credentials",
			Description: "Using default or weak credentials in configuration files.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-798",
			Remediation: "Use strong, randomly generated passwords loaded from environment variables.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)header\s*\(\s*['"]X-Powered-By:\s*PHP.*['"]\s*\)`),
		Rule: rules.Rule{
			ID:          "PHP-A02-004",
			Title:       "Information Exposure via Headers",
			Description: "Exposing the server technology stack via X-Powered-By headers.",
			Severity:    rules.SeverityInfo,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-200",
			Remediation: "Remove the X-Powered-By header. Set expose_php = Off in php.ini.",
		},
	},

	// A04 - Cryptographic Failures
	{
		Regex: regexp.MustCompile(`(?i)(?:md5|sha1)\s*\(\s*\$_(?:POST|GET|REQUEST)\[['"]password['"]\]\s*\)`),
		Rule: rules.Rule{
			ID:          "PHP-A04-001",
			Title:       "Weak Password Hashing (MD5/SHA1)",
			Description: "MD5 and SHA1 are computationally weak and easily cracked. Do not use for passwords.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-328",
			Remediation: "Use password_hash() with PASSWORD_DEFAULT or PASSWORD_BCRYPT/ARGON2.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:rand|mt_rand|uniqid)\s*\(`),
		Rule: rules.Rule{
			ID:          "PHP-A04-002",
			Title:       "Weak Random Number Generator",
			Description: "rand(), mt_rand(), and uniqid() are not cryptographically secure.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-338",
			Remediation: "Use random_bytes() or random_int() for generating secure random values.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:api_key|apikey|secret_key|token)\s*=\s*['"][A-Za-z0-9_-]{20,}['"]`),
		Rule: rules.Rule{
			ID:          "PHP-A04-003",
			Title:       "Hardcoded Secret / API Key",
			Description: "Storing secrets or API keys in source code is insecure.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-798",
			Remediation: "Load secrets from secure environment variables or a secrets management service.",
		},
	},

	// A05 - Injection
	{
		Regex: regexp.MustCompile(`(?i)(?:mysql_query|mysqli_query|pg_query)\s*\(\s*.*?['"]\s*\.\s*\$(?:_GET|_POST|_REQUEST)[a-zA-Z0-9_\[\]'"]*\s*\.\s*['"]`),
		Rule: rules.Rule{
			ID:          "PHP-A05-001",
			Title:       "SQL Injection via String Concatenation",
			Description: "Concatenating user input directly into SQL queries allows SQL injection.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-89",
			Remediation: "Use prepared statements with parameterized queries (e.g., via PDO or MySQLi).",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:echo|print|printf)\s*\(?\s*.*?\$(?:_GET|_POST|_REQUEST|_COOKIE)[a-zA-Z0-9_\[\]'"]*`),
		Rule: rules.Rule{
			ID:          "PHP-A05-002",
			Title:       "Cross-Site Scripting (XSS) via Unsanitized Input",
			Description: "Directly outputting user input without encoding can lead to Reflected XSS.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Use htmlspecialchars() with ENT_QUOTES | ENT_HTML5 to escape output.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(\s*.*?\$(?:_GET|_POST|_REQUEST)[a-zA-Z0-9_\[\]'"]*`),
		Rule: rules.Rule{
			ID:          "PHP-A05-003",
			Title:       "OS Command Injection",
			Description: "Passing user input to system shell execution functions enables OS command injection.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-78",
			Remediation: "Avoid shelling out if possible. If required, use escapeshellarg() and escapeshellcmd().",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\[`),
		Rule: rules.Rule{
			ID:          "PHP-A05-004",
			Title:       "Local/Remote File Inclusion (LFI/RFI)",
			Description: "Directly including files based on user input can execute arbitrary code.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-98",
			Remediation: "Use a mapping or allowlist for includes. Never use user input directly in include/require.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]*\/e['"imsxu]*\s*,`),
		Rule: rules.Rule{
			ID:          "PHP-A05-005",
			Title:       "Code Injection via preg_replace /e",
			Description: "The /e modifier evaluates the replacement string as PHP code, leading to Remote Code Execution.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-94",
			Remediation: "Use preg_replace_callback() instead. The /e modifier is deprecated in PHP 5.5.0 and removed in PHP 7.0.0.",
		},
	},

	// A06 - Insecure Design
	{
		Regex: regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*['"]post['"][^>]*>`),
		Rule: rules.Rule{
			ID:          "PHP-A06-001",
			Title:       "Missing CSRF Token in Form",
			Description: "State-changing forms may lack anti-CSRF tokens, allowing Cross-Site Request Forgery.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA06,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-352",
			Remediation: "Implement an anti-CSRF token pattern for all state-changing operations.",
		},
	},

	// A07 - Authentication Failures
	{
		Regex: regexp.MustCompile(`(?i)ini_set\s*\(\s*['"]session\.cookie_httponly['"]\s*,\s*(?:0|false|['"]0['"])`),
		Rule: rules.Rule{
			ID:          "PHP-A07-001",
			Title:       "Session Cookie HttpOnly Disabled",
			Description: "Disabling HttpOnly for session cookies allows client-side scripts to access them (XSS session hijacking).",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1004",
			Remediation: "Ensure session.cookie_httponly is set to 1.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)ini_set\s*\(\s*['"]session\.cookie_secure['"]\s*,\s*(?:0|false|['"]0['"])`),
		Rule: rules.Rule{
			ID:          "PHP-A07-002",
			Title:       "Session Cookie Secure Disabled",
			Description: "Session cookies transmitted over unencrypted HTTP connections can be intercepted.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-614",
			Remediation: "Set session.cookie_secure to 1 and ensure HTTPS is used.",
		},
	},

	// A08 - Software or Data Integrity Failures
	{
		Regex: regexp.MustCompile(`(?i)unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[`),
		Rule: rules.Rule{
			ID:          "PHP-A08-001",
			Title:       "Insecure Deserialization",
			Description: "Deserializing user-supplied input can lead to object injection and Remote Code Execution.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-502",
			Remediation: "Use a safe data format like JSON (json_decode) instead of serialize/unserialize.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)eval\s*\(`),
		Rule: rules.Rule{
			ID:          "PHP-A08-002",
			Title:       "Use of eval()",
			Description: "The eval() function executes arbitrary PHP code. It is extremely dangerous.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-95",
			Remediation: "Refactor code to avoid the use of eval().",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)assert\s*\(\s*\$_(?:GET|POST|REQUEST)\[`),
		Rule: rules.Rule{
			ID:          "PHP-A08-003",
			Title:       "Assertion Injection",
			Description: "Using assert() with user-controlled strings can lead to arbitrary code execution.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-615",
			Remediation: "Do not use assert() to evaluate string-based user input. In PHP 7.2+, assert() string evaluation is deprecated.",
		},
	},

	// A09 - Security Logging and Monitoring Failures
	{
		Regex: regexp.MustCompile(`(?i)error_log\s*\(\s*.*?(?:password|pwd|secret|token).*?\)`),
		Rule: rules.Rule{
			ID:          "PHP-A09-001",
			Title:       "Sensitive Data in Logs",
			Description: "Logging sensitive variables like passwords or tokens may expose them.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA09,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-532",
			Remediation: "Sanitize log entries to ensure no sensitive credentials or tokens are logged.",
		},
	},

	// A10 - Mishandling of Exceptional Conditions
	{
		Regex: regexp.MustCompile(`(?i)catch\s*\(\s*[a-zA-Z\\]*Exception\s+\$\w+\s*\)\s*\{\s*\}`),
		Rule: rules.Rule{
			ID:          "PHP-A10-001",
			Title:       "Empty Catch Block",
			Description: "Silently catching exceptions without handling or logging hides application failures and may leave the system in an inconsistent state.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTRespond},
			CWE:         "CWE-391",
			Remediation: "Log the exception and implement appropriate error recovery or reporting mechanisms.",
		},
	},
	{
		Regex: regexp.MustCompile(`(?i)(?:echo|print|die|exit)\s*\(?\s*\$e->getMessage\(\)\s*\)?`),
		Rule: rules.Rule{
			ID:          "PHP-A10-002",
			Title:       "Exception Message Exposure",
			Description: "Displaying raw exception messages directly to users may expose sensitive internal system details.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-209",
			Remediation: "Log the exception message securely on the server and present a generic error message to the user.",
		},
	},
}
