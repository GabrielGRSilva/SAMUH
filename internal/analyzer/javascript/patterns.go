package javascript

import (
	"regexp"
	"samuh/internal/rules"
)

type pattern struct {
	regex *regexp.Regexp
	rule  rules.Rule
}

var jsPatterns = []pattern{
	// A01 - Broken Access Control
	{
		regex: regexp.MustCompile(`(?i)(if|switch)\s*\(\s*(user\.role|role|user\.isAdmin|isAdmin)\s*(===|==|!==|!=)\s*['"](admin|root|superuser)['"]\s*\)\s*\{`),
		rule: rules.Rule{
			ID:          "JS-BAC-001",
			Title:       "Client-Side Role Check",
			Description: "Client-side code checks user roles to enforce access control. This can be bypassed by an attacker modifying the client code or state.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTGovern, rules.NISTProtect},
			CWE:         "CWE-602",
			Remediation: "Enforce access controls on the server side. Client-side checks should only be used for UI state, not for actual security enforcement.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)window\.location(\.(href|replace|assign))?\s*=\s*[^;]+(url|redirect|target|next|return|path|href)[^;]*;`),
		rule: rules.Rule{
			ID:          "JS-BAC-002",
			Title:       "Potential Open Redirect",
			Description: "Dynamic value used for window.location redirection, potentially allowing open redirect attacks.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-601",
			Remediation: "Validate the target URL against a strict allowlist or ensure it is a relative path before redirecting.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)fetch\s*\(\s*['"]/api/[a-zA-Z0-9_/-]+['"]\s*[,)]`),
		rule: rules.Rule{
			ID:          "JS-BAC-003",
			Title:       "API Call Without Authorization Header",
			Description: "API endpoints are called without an authorization header, which may indicate a missing authentication check or exposed endpoints.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA01,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-862",
			Remediation: "Ensure sensitive API endpoints require authorization and include the appropriate token in the request headers.",
		},
	},

	// A02 - Security Misconfiguration
	{
		regex: regexp.MustCompile(`(?i)\/\/\s*eslint-disable(?:-next-line)?\s+(?:.*security|.*no-eval|.*no-implied-eval|.*no-new-func)`),
		rule: rules.Rule{
			ID:          "JS-SMC-001",
			Title:       "Security Linter Rules Disabled",
			Description: "Security-related ESLint rules have been explicitly disabled, which may mask vulnerabilities.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTGovern, rules.NISTIdentify},
			CWE:         "CWE-573",
			Remediation: "Remove eslint-disable comments for security rules and fix the underlying issues.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\/\/#\s*sourceMappingURL=.*`),
		rule: rules.Rule{
			ID:          "JS-SMC-002",
			Title:       "Source Maps Enabled",
			Description: "Source maps are exposed, which can leak application logic and sensitive information to attackers.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-538",
			Remediation: "Disable source maps in production builds.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)as\s+any\s*(=|;|\)|,)`),
		rule: rules.Rule{
			ID:          "JS-SMC-003",
			Title:       "TypeScript 'any' Type Casting",
			Description: "Using 'as any' bypasses TypeScript's type checking, potentially leading to security issues if handling user input.",
			Severity:    rules.SeverityInfo,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA02,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-704",
			Remediation: "Use precise types instead of 'any', or use 'unknown' and perform type narrowing with type guards.",
		},
	},

	// A03 - Software Supply Chain Failures
	{
		regex: regexp.MustCompile(`(?i)<script\s+[^>]*src\s*=\s*['"]https?://[^'"]+['"][^>]*>`),
		rule: rules.Rule{
			ID:          "JS-SSC-001",
			Title:       "Missing Subresource Integrity (SRI)",
			Description: "Loading an external script without an integrity attribute, making the application vulnerable if the CDN is compromised.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA03,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-829",
			Remediation: "Add an 'integrity' attribute with the cryptographic hash of the script.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)import\s+.*\s+from\s+['"]http:\/\/[^'"]+['"]`),
		rule: rules.Rule{
			ID:          "JS-SSC-002",
			Title:       "Insecure HTTP Import",
			Description: "Importing a module over plain HTTP instead of HTTPS, allowing man-in-the-middle (MitM) attacks.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA03,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-319",
			Remediation: "Use HTTPS for all module imports.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)import\s*\(\s*[^'"` + "`" + `)]+\s*\)`),
		rule: rules.Rule{
			ID:          "JS-SSC-003",
			Title:       "Dynamic Import with Variable",
			Description: "Dynamic import() using a variable can lead to loading unintended or malicious modules if the path is user-controlled.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA03,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-94",
			Remediation: "Ensure dynamic import paths are strictly validated or use an allowlist.",
		},
	},

	// A04 - Cryptographic Failures
	{
		regex: regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9\-_]{16,}['"]`),
		rule: rules.Rule{
			ID:          "JS-CRY-001",
			Title:       "Hardcoded Credentials",
			Description: "Sensitive credentials such as API keys or secrets are hardcoded in the source code.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-798",
			Remediation: "Store credentials securely using environment variables or a secrets manager.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\b(btoa|atob)\s*\(`),
		rule: rules.Rule{
			ID:          "JS-CRY-002",
			Title:       "Base64 Used as Encryption",
			Description: "Base64 encoding (btoa/atob) provides no cryptographic security and should not be used to protect sensitive data.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-327",
			Remediation: "Use strong encryption algorithms via the WebCrypto API for data confidentiality.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)Math\.random\s*\(`),
		rule: rules.Rule{
			ID:          "JS-CRY-003",
			Title:       "Insecure Randomness",
			Description: "Math.random() is not cryptographically secure and should not be used for security-sensitive operations.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA04,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-338",
			Remediation: "Use window.crypto.getRandomValues() for secure random number generation.",
		},
	},

	// A05 - Injection
	{
		regex: regexp.MustCompile(`(?i)\.(innerHTML|outerHTML)\s*=`),
		rule: rules.Rule{
			ID:          "JS-INJ-001",
			Title:       "DOM XSS via innerHTML",
			Description: "Assigning values directly to innerHTML/outerHTML can lead to Cross-Site Scripting (XSS) if the data is untrusted.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Use textContent or DOM manipulation methods (createElement) instead, or sanitize input using DOMPurify.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)document\.write(?:ln)?\s*\(`),
		rule: rules.Rule{
			ID:          "JS-INJ-002",
			Title:       "DOM XSS via document.write",
			Description: "Using document.write() with user input can lead to XSS vulnerabilities.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Avoid document.write(). Use safe DOM manipulation methods instead.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^}]+\}\s*\}`),
		rule: rules.Rule{
			ID:          "JS-INJ-003",
			Title:       "React dangerouslySetInnerHTML",
			Description: "Using dangerouslySetInnerHTML in React bypasses built-in XSS protections.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Ensure data passed to dangerouslySetInnerHTML is strictly sanitized, or use standard React rendering.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)v-html\s*=\s*['"][^'"]+['"]`),
		rule: rules.Rule{
			ID:          "JS-INJ-004",
			Title:       "Vue v-html Directive",
			Description: "Using the v-html directive in Vue renders raw HTML and can lead to XSS if the content is untrusted.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Sanitize the content before binding it to v-html, or use standard text interpolation ({{ }}).",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\[innerHTML\]\s*=\s*['"][^'"]+['"]`),
		rule: rules.Rule{
			ID:          "JS-INJ-005",
			Title:       "Angular innerHTML Binding",
			Description: "Binding data directly to [innerHTML] in Angular bypasses some security contexts, potentially leading to XSS.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-79",
			Remediation: "Ensure data is properly sanitized by Angular's DomSanitizer before binding.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\b(eval|setTimeout|setInterval|new\s+Function)\s*\(\s*[^)]*(?:\+|` + "`" + `)`),
		rule: rules.Rule{
			ID:          "JS-INJ-006",
			Title:       "Code Injection via eval/setTimeout",
			Description: "Using eval(), new Function(), setTimeout(), or setInterval() with dynamic strings allows arbitrary code execution.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-94",
			Remediation: "Avoid these functions entirely or pass function references instead of strings.",
		},
	},
	{
		regex: regexp.MustCompile("(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)[\\s\\w*]+(FROM|INTO|SET|TABLE)\\s+[\\w\\.]+\\s+.*\\$\\{[^}]+\\}"),
		rule: rules.Rule{
			ID:          "JS-INJ-007",
			Title:       "SQL Injection in Template Literal",
			Description: "Interpolating variables directly into SQL queries using template literals creates a high risk of SQL injection.",
			Severity:    rules.SeverityCritical,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA05,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-89",
			Remediation: "Use parameterized queries or prepared statements via your database driver.",
		},
	},

	// A06 - Insecure Design
	{
		regex: regexp.MustCompile(`(?i)<meta\s+http-equiv=['"]Content-Security-Policy['"]\s+content=['"][^'"]*(?:unsafe-inline|unsafe-eval)[^'"]*['"]\s*\/?>`),
		rule: rules.Rule{
			ID:          "JS-ID-001",
			Title:       "Insecure Content Security Policy",
			Description: "CSP contains unsafe directives (unsafe-inline or unsafe-eval), reducing its effectiveness against XSS.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA06,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1021",
			Remediation: "Remove unsafe-inline and unsafe-eval from CSP and use nonces or hashes for scripts.",
		},
	},

	// A07 - Authentication Failures
	{
		regex: regexp.MustCompile(`(?i)(localStorage|sessionStorage)\.setItem\s*\(\s*['"](token|jwt|auth|access_token|refresh_token)['"]\s*,`),
		rule: rules.Rule{
			ID:          "JS-AF-001",
			Title:       "Tokens Stored in Web Storage",
			Description: "Sensitive tokens stored in localStorage or sessionStorage are accessible to any JavaScript running on the page, making them vulnerable to XSS.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-922",
			Remediation: "Store authentication tokens in secure, HttpOnly cookies.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)[\?&](token|password|secret)=[^&"']+`),
		rule: rules.Rule{
			ID:          "JS-AF-002",
			Title:       "Credentials in URL",
			Description: "Sensitive data is passed via URL parameters, where it can be logged in browser history, proxy logs, or referer headers.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA07,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-598",
			Remediation: "Pass sensitive credentials securely in the request body (POST) or in HTTP headers.",
		},
	},

	// A08 - Software or Data Integrity Failures
	{
		regex: regexp.MustCompile(`(?i)(\b__proto__\b|\bconstructor\.prototype\b)`),
		rule: rules.Rule{
			ID:          "JS-DIF-001",
			Title:       "Prototype Pollution Vulnerability",
			Description: "Direct use of __proto__ or constructor.prototype can lead to prototype pollution, altering object behavior.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceLow,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1321",
			Remediation: "Avoid direct manipulation of prototypes. Use Object.create(null) for dictionary objects.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\.postMessage\s*\(\s*[^,]+\s*,\s*['"]\*['"]\s*\)`),
		rule: rules.Rule{
			ID:          "JS-DIF-002",
			Title:       "Insecure postMessage Origin",
			Description: "Sending a postMessage with an origin of '*' allows any listening window to receive the message.",
			Severity:    rules.SeverityHigh,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA08,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-345",
			Remediation: "Specify the exact target origin when using postMessage to ensure confidentiality.",
		},
	},

	// A09 - Security Logging and Monitoring Failures
	{
		regex: regexp.MustCompile(`(?i)console\.(log|dir|trace|debug)\s*\(\s*.*(password|secret|token|key|pwd).*\)`),
		rule: rules.Rule{
			ID:          "JS-LF-001",
			Title:       "Sensitive Data Logged to Console",
			Description: "Logging sensitive information to the console can expose it to anyone who inspects the browser developer tools.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceMedium,
			OWASP:       rules.OWASPA09,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-532",
			Remediation: "Remove console statements that log sensitive data, especially in production environments.",
		},
	},

	// A10 - Mishandling of Exceptional Conditions
	{
		regex: regexp.MustCompile(`(?i)catch\s*\(\s*[^)]*\)\s*\{\s*\}`),
		rule: rules.Rule{
			ID:          "JS-MEC-001",
			Title:       "Empty Catch Block",
			Description: "Catching an exception but taking no action (empty block). This swallows errors and can hide security or logical issues.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTDetect, rules.NISTRespond},
			CWE:         "CWE-390",
			Remediation: "Handle the exception appropriately by logging the error or returning a safe state.",
		},
	},
	{
		regex: regexp.MustCompile(`(?i)\.catch\s*\(\s*(?:function\s*\([^)]*\)\s*\{\s*\}|\([^)]*\)\s*=>\s*\{\s*\})\s*\)`),
		rule: rules.Rule{
			ID:          "JS-MEC-002",
			Title:       "Empty Promise Catch",
			Description: "A Promise rejection is caught but ignored, which can lead to unhandled exceptional conditions and inconsistent application state.",
			Severity:    rules.SeverityLow,
			Confidence:  rules.ConfidenceHigh,
			OWASP:       rules.OWASPA10,
			NIST:        []rules.NISTFunction{rules.NISTDetect, rules.NISTRespond},
			CWE:         "CWE-390",
			Remediation: "Properly handle promise rejections, log them, or alert the user.",
		},
	},
}
