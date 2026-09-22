package node

import (
	"regexp"
	"samuh/internal/rules"
)

type pattern struct {
	regex *regexp.Regexp
	rule  rules.Rule
}

var nodePatterns = []pattern{
	// A01 - Broken Access Control
	{
		regex: regexp.MustCompile(`(?i)cors\(\s*\{\s*origin:\s*(['"]\*['"]|true)`),
		rule: rules.Rule{
			ID:          "NODE-A01-001",
			Title:       "Permissive CORS Configuration",
			Description: "Cross-Origin Resource Sharing (CORS) is configured to allow any origin ('*') or dynamically reflects the request origin (true). This can expose sensitive endpoints to malicious domains.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-942",
			Remediation: "Specify an explicit, restrictive list of allowed origins.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?i)path\.join\([^)]*req\.(query|body|params)\.[a-zA-Z0-9_]+[^)]*\)`),
		rule: rules.Rule{
			ID:          "NODE-A01-002",
			Title:       "Potential Directory Traversal",
			Description: "User input is passed directly to path.join(), which may allow directory traversal (e.g., using '../') to access arbitrary files.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-22",
			Remediation: "Validate and sanitize user input. Ensure the resolved path resides within the expected base directory.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?i)(?:axios|fetch|http|https)\.(?:get|post|put|delete|request)\s*\(\s*(?:req\.(query|body|params)\.[a-zA-Z0-9_]+|.*` + "`" + `\$\{req\.(query|body|params)\.[a-zA-Z0-9_]+\}` + "`" + `)`),
		rule: rules.Rule{
			ID:          "NODE-A01-003",
			Title:       "Potential Server-Side Request Forgery (SSRF)",
			Description: "User-controlled input is used to construct a URL for a server-side request. This can allow attackers to probe internal networks.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-918",
			Remediation: "Validate URLs against an allowlist of permitted destinations. Do not blindly construct URLs from user input.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`app\.(get|post|put|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:req,\s*res\s*=>|function\s*\(req,\s*res\))`),
		rule: rules.Rule{
			ID:          "NODE-A01-004",
			Title:       "Missing Authentication Middleware on Route",
			Description: "A route handler is defined without any preceding middleware. This might indicate missing authentication or authorization checks.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-306",
			Remediation: "Ensure sensitive routes have authentication and authorization middleware applied before the request handler.",
			Languages:   []string{"Node.js"},
		},
	},

	// A02 - Security Misconfiguration
	{
		regex: regexp.MustCompile(`app\.set\(['"]env['"],\s*['"]development['"]\)`),
		rule: rules.Rule{
			ID:          "NODE-A02-001",
			Title:       "Hardcoded Development Environment",
			Description: "The application environment is hardcoded to 'development'. This often enables verbose errors and disables security features.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-16",
			Remediation: "Use environment variables (e.g., process.env.NODE_ENV) to configure the environment dynamically.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`express\.static\(['"]\/?(?:etc|var|usr|opt|home|\.git|\.env|/)['"]\)`),
		rule: rules.Rule{
			ID:          "NODE-A02-002",
			Title:       "Sensitive Directory Exposure via Static Serving",
			Description: "Express is configured to serve a sensitive system or hidden directory statically.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-552",
			Remediation: "Only serve necessary public assets from a dedicated public directory.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`res\.send\([^)]*err\.stack[^)]*\)|res\.status\([^)]*\)\.send\(err\)`),
		rule: rules.Rule{
			ID:          "NODE-A02-003",
			Title:       "Verbose Error Details Sent to Client",
			Description: "Stack traces or full error objects are sent directly in the HTTP response, leaking internal application details.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-209",
			Remediation: "Log the error internally and return a generic error message to the client.",
			Languages:   []string{"Node.js"},
		},
	},

	// A04 - Cryptographic Failures
	{
		regex: regexp.MustCompile(`(?i)createHash\(['"](md5|sha1)['"]\)`),
		rule: rules.Rule{
			ID:          "NODE-A04-001",
			Title:       "Weak Hashing Algorithm (MD5/SHA1)",
			Description: "Use of MD5 or SHA1 for hashing is insecure. These algorithms are vulnerable to collision attacks.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-328",
			Remediation: "Use strong hashing algorithms like SHA-256 (sha256) or SHA-3.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`Math\.random\(\)`),
		rule: rules.Rule{
			ID:          "NODE-A04-002",
			Title:       "Insecure Randomness (Math.random)",
			Description: "Math.random() produces predictable values and is not suitable for cryptographic or security-sensitive operations.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-338",
			Remediation: "Use the crypto module's randomBytes or randomInt functions for secure randomness.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?i)jwt\.sign\([^,]+,\s*(?:['"]['"]|['"]secret['"]|['"]password['"]|['"]123456['"])`),
		rule: rules.Rule{
			ID:          "NODE-A04-003",
			Title:       "Hardcoded Weak JWT Secret",
			Description: "A weak or empty hardcoded secret is used for signing JSON Web Tokens.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-798",
			Remediation: "Use strong, randomly generated secrets injected via environment variables.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?i)algorithm:\s*['"]none['"]`),
		rule: rules.Rule{
			ID:          "NODE-A04-004",
			Title:       "JWT 'none' Algorithm",
			Description: "JWT algorithm is set to 'none', completely disabling signature verification.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-347",
			Remediation: "Ensure a strong algorithm (e.g., HS256, RS256) is mandated when validating JWTs.",
			Languages:   []string{"Node.js"},
		},
	},

	// A05 - Injection
	{
		regex: regexp.MustCompile(`(?i)(?:eval|new Function|setTimeout|setInterval)\s*\(\s*(?:req\.(query|body|params)\.[a-zA-Z0-9_]+|.*req\.(query|body|params)\.[a-zA-Z0-9_]+)`),
		rule: rules.Rule{
			ID:          "NODE-A05-001",
			Title:       "Potential Code Injection (eval)",
			Description: "User input is passed to a code execution function like eval() or Function constructor.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-94",
			Remediation: "Avoid using eval() or Function constructors. Use safer alternatives for parsing or executing logic.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?:child_process\.)?(?:exec|execSync)\s*\([^,]*\+.*req\.(query|body|params)\.[a-zA-Z0-9_]+`),
		rule: rules.Rule{
			ID:          "NODE-A05-002",
			Title:       "Command Injection in exec()",
			Description: "User input is concatenated into a system command executed via child_process.exec(), enabling command injection.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-78",
			Remediation: "Use child_process.execFile or spawn instead, and pass arguments as an array rather than a single string.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`\.(?:query|sequelize\.query)\s*\([^,]*\+.*req\.(query|body|params)\.[a-zA-Z0-9_]+`),
		rule: rules.Rule{
			ID:          "NODE-A05-003",
			Title:       "SQL Injection (String Concatenation)",
			Description: "A SQL query is constructed by concatenating user input instead of using parameterized queries.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-89",
			Remediation: "Use parameterized queries or prepared statements provided by your database driver or ORM.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`\.(?:find|findOne|update|remove|delete)\s*\(\s*req\.(query|body|params)`),
		rule: rules.Rule{
			ID:          "NODE-A05-004",
			Title:       "NoSQL Injection",
			Description: "Raw user input objects (e.g., req.body) are passed directly to MongoDB/NoSQL query functions.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-943",
			Remediation: "Validate and extract specific fields from user input. Do not pass the entire req.body or req.query object directly to the database.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?:ejs\.render|pug\.render|handlebars\.compile)\s*\([^,]*req\.(query|body|params)\.[a-zA-Z0-9_]+`),
		rule: rules.Rule{
			ID:          "NODE-A05-005",
			Title:       "Server-Side Template Injection (SSTI)",
			Description: "User input is passed directly to a template engine's render or compile function as the template string itself.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1336",
			Remediation: "Only use trusted, predefined template strings. Pass user input as template variables, not as the template structure.",
			Languages:   []string{"Node.js"},
		},
	},

	// A06 - Insecure Design
	{
		regex: regexp.MustCompile(`csrf\(\s*(?:\{\s*ignoreMethods:\s*\[[^\]]+['"](?:GET|POST|PUT|DELETE)['"][^\]]+\])?\)`),
		// Since regex for "missing" CSRF is hard, we look for misconfigured CSRF or we just provide this placeholder.
		// Let's actually look for disabled CSRF protection in express apps.
		rule: rules.Rule{
			ID:          "NODE-A06-001",
			Title:       "Disabled CSRF Protection",
			Description: "CSRF protection might be explicitly disabled or improperly configured for modifying HTTP methods.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA06,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-352",
			Remediation: "Implement robust CSRF protection (e.g., csurf middleware) for all state-changing endpoints.",
			Languages:   []string{"Node.js"},
		},
	},
	// We'll catch missing rate-limit at the package.json level later.

	// A07 - Authentication Failures
	{
		regex: regexp.MustCompile(`(?:password|pass|pwd)\s*(?:===|==|!==|!=)\s*(?:req\.body\.(?:password|pass|pwd)|[a-zA-Z0-9_]+\.password)`),
		rule: rules.Rule{
			ID:          "NODE-A07-001",
			Title:       "Plaintext Password Comparison",
			Description: "Passwords are being compared using strict equality instead of a secure timing-safe or hashing comparison (like bcrypt).",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-256",
			Remediation: "Use bcrypt.compare() or similar functions to safely verify hashed passwords.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`session\(\s*\{\s*secret:\s*['"][a-zA-Z0-9]+['"]`),
		rule: rules.Rule{
			ID:          "NODE-A07-002",
			Title:       "Hardcoded Session Secret",
			Description: "The express-session middleware is configured with a hardcoded, literal secret.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-798",
			Remediation: "Use a strong, random secret injected via environment variables.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`cookie:\s*\{\s*(?:secure:\s*false|httpOnly:\s*false)`),
		rule: rules.Rule{
			ID:          "NODE-A07-003",
			Title:       "Insecure Session Cookie Configuration",
			Description: "Session cookies are explicitly configured to lack 'secure' or 'httpOnly' flags, making them vulnerable to XSS and network interception.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-614",
			Remediation: "Ensure 'secure: true' (in production) and 'httpOnly: true' are set for session cookies.",
			Languages:   []string{"Node.js"},
		},
	},

	// A08 - Data Integrity Failures
	{
		regex: regexp.MustCompile(`(?:serialize\.unserialize|deserialize)\s*\(\s*req\.(query|body|params)\.[a-zA-Z0-9_]+`),
		rule: rules.Rule{
			ID:          "NODE-A08-001",
			Title:       "Insecure Deserialization",
			Description: "Untrusted user data is passed to a deserialization function, which can lead to remote code execution.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-502",
			Remediation: "Use safe data formats like JSON.parse(). Avoid using packages like node-serialize with untrusted input.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`(?:Object\.assign|lodash\.merge|_\.merge)\s*\(\s*(?:\{\}|[a-zA-Z0-9_]+)\s*,\s*req\.(query|body|params)\.[a-zA-Z0-9_]+`),
		rule: rules.Rule{
			ID:          "NODE-A08-002",
			Title:       "Potential Prototype Pollution",
			Description: "User input is directly merged or assigned into objects, which may lead to prototype pollution.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1321",
			Remediation: "Use robust merging libraries that protect against prototype pollution or validate input structures thoroughly.",
			Languages:   []string{"Node.js"},
		},
	},

	// A09 - Logging Failures
	{
		regex: regexp.MustCompile(`console\.(?:log|error|warn|info)\s*\([^)]*(?:password|token|secret|key)[^)]*\)`),
		rule: rules.Rule{
			ID:          "NODE-A09-001",
			Title:       "Sensitive Data Logged",
			Description: "The application logs variables or objects that likely contain sensitive data (passwords, tokens, secrets).",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA09,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-532",
			Remediation: "Redact or mask sensitive information before logging.",
			Languages:   []string{"Node.js"},
		},
	},

	// A10 - Mishandling of Exceptional Conditions
	{
		regex: regexp.MustCompile(`catch\s*\(\s*[a-zA-Z0-9_]+\s*\)\s*\{\s*\}`),
		rule: rules.Rule{
			ID:          "NODE-A10-001",
			Title:       "Empty Catch Block",
			Description: "An exception is caught but silently ignored, masking errors and potentially leaving the application in an inconsistent state.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTRespond},
			CWE:         "CWE-391",
			Remediation: "Properly handle the error by logging it, recovering, or returning an appropriate response.",
			Languages:   []string{"Node.js"},
		},
	},
	{
		regex: regexp.MustCompile(`process\.on\(['"]uncaughtException['"],\s*(?:[a-zA-Z0-9_]+\s*=>|function\s*\([a-zA-Z0-9_]+\))\s*\{\s*console\.log[^}]*\}\)`),
		rule: rules.Rule{
			ID:          "NODE-A10-002",
			Title:       "Improper UncaughtException Handling",
			Description: "The uncaughtException event is handled merely by logging, without crashing the process. This can leave Node.js in an undefined state.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTRespond},
			CWE:         "CWE-391",
			Remediation: "Log the error and then forcefully exit the process (process.exit(1)) to allow a process manager to restart it cleanly.",
			Languages:   []string{"Node.js"},
		},
	},
}
