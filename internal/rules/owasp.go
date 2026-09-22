// Package rules - owasp.go provides the OWASP Top 10:2025 catalog with
// detailed descriptions and CWE mappings for each category.
package rules

// OWASPInfo contains details about an OWASP Top 10:2025 category.
type OWASPInfo struct {
	// ID is the short identifier (e.g., "A01:2025").
	ID string

	// Name is the human-readable category name.
	Name string

	// Description explains what the category covers.
	Description string

	// URL links to the official OWASP page for this category.
	URL string

	// CWEs lists common CWE identifiers associated with this category.
	CWEs []string
}

// OWASPCatalog maps each OWASP Top 10:2025 category to its detailed information.
var OWASPCatalog = map[OWASPCategory]OWASPInfo{
	OWASPA01: {
		ID:          "A01:2025",
		Name:        "Broken Access Control",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data. SSRF is now included in this category.",
		URL:         "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		CWEs:        []string{"CWE-22", "CWE-287", "CWE-352", "CWE-918"},
	},
	OWASPA02: {
		ID:          "A02:2025",
		Name:        "Security Misconfiguration",
		Description: "Security misconfiguration is a commonly seen issue resulting from insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
		URL:         "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		CWEs:        []string{"CWE-16", "CWE-611", "CWE-1004"},
	},
	OWASPA03: {
		ID:          "A03:2025",
		Name:        "Software Supply Chain Failures",
		Description: "Risks from using software components that are out of date, vulnerable, or untrusted. Expanded from the previous 'Vulnerable and Outdated Components' to include CI/CD pipelines, lockfile integrity, and software distribution ecosystem risks.",
		URL:         "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		CWEs:        []string{"CWE-937", "CWE-1035", "CWE-1104", "CWE-829"},
	},
	OWASPA04: {
		ID:          "A04:2025",
		Name:        "Cryptographic Failures",
		Description: "Failures related to cryptography (or lack thereof) which often lead to sensitive data exposure. Includes weak algorithms, hardcoded secrets, missing encryption, and improper key management.",
		URL:         "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		CWEs:        []string{"CWE-310", "CWE-327", "CWE-330", "CWE-798"},
	},
	OWASPA05: {
		ID:          "A05:2025",
		Name:        "Injection",
		Description: "Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter as part of a command or query. Includes Cross-Site Scripting (XSS).",
		URL:         "https://owasp.org/Top10/A03_2021-Injection/",
		CWEs:        []string{"CWE-79", "CWE-89", "CWE-94", "CWE-78"},
	},
	OWASPA06: {
		ID:          "A06:2025",
		Name:        "Insecure Design",
		Description: "A broad category representing different weaknesses expressed as missing or ineffective control design. Emphasizes the need for threat modeling, secure design patterns, and reference architectures.",
		URL:         "https://owasp.org/Top10/A04_2021-Insecure_Design/",
		CWEs:        []string{"CWE-209", "CWE-256", "CWE-501", "CWE-522"},
	},
	OWASPA07: {
		ID:          "A07:2025",
		Name:        "Authentication Failures",
		Description: "Failures in identity confirmation, authentication, and session management that can allow attackers to compromise passwords, keys, session tokens, or exploit implementation flaws.",
		URL:         "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		CWEs:        []string{"CWE-287", "CWE-384", "CWE-798", "CWE-307"},
	},
	OWASPA08: {
		ID:          "A08:2025",
		Name:        "Software or Data Integrity Failures",
		Description: "Failures related to code and infrastructure that does not protect against integrity violations. Includes insecure deserialization, missing integrity checks, and unsigned software updates.",
		URL:         "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
		CWEs:        []string{"CWE-494", "CWE-502", "CWE-829", "CWE-830"},
	},
	OWASPA09: {
		ID:          "A09:2025",
		Name:        "Security Logging and Monitoring Failures",
		Description: "Without sufficient logging and monitoring, breaches cannot be detected. Includes insufficient logging of auditable events, lack of alerting, and sensitive data exposure in logs.",
		URL:         "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
		CWEs:        []string{"CWE-117", "CWE-223", "CWE-532", "CWE-778"},
	},
	OWASPA10: {
		ID:          "A10:2025",
		Name:        "Mishandling of Exceptional Conditions",
		Description: "New in 2025. Failures in properly handling error conditions, exceptions, and edge cases. Includes empty catch blocks, leaked stack traces, swallowed security errors, and missing error handling on critical operations.",
		URL:         "https://owasp.org/Top10/",
		CWEs:        []string{"CWE-209", "CWE-390", "CWE-754", "CWE-755"},
	},
}
