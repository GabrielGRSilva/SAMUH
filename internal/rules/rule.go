// Package rules defines the core types for security rules, findings, and
// compliance framework mappings used throughout SAMUH.
package rules

import "fmt"

// Severity represents the impact level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityRank returns a numeric rank for sorting (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// IsAtLeast returns true if this severity is at least as severe as other.
func (s Severity) IsAtLeast(other Severity) bool {
	return s.Rank() >= other.Rank()
}

// OWASPCategory represents an OWASP Top 10:2025 category.
type OWASPCategory string

const (
	OWASPA01 OWASPCategory = "A01:2025-Broken Access Control"
	OWASPA02 OWASPCategory = "A02:2025-Security Misconfiguration"
	OWASPA03 OWASPCategory = "A03:2025-Software Supply Chain Failures"
	OWASPA04 OWASPCategory = "A04:2025-Cryptographic Failures"
	OWASPA05 OWASPCategory = "A05:2025-Injection"
	OWASPA06 OWASPCategory = "A06:2025-Insecure Design"
	OWASPA07 OWASPCategory = "A07:2025-Authentication Failures"
	OWASPA08 OWASPCategory = "A08:2025-Software or Data Integrity Failures"
	OWASPA09 OWASPCategory = "A09:2025-Security Logging and Monitoring Failures"
	OWASPA10 OWASPCategory = "A10:2025-Mishandling of Exceptional Conditions"
)

// NISTFunction represents a NIST CSF 2.0 function.
type NISTFunction string

const (
	NISTGovern   NISTFunction = "GV-Govern"
	NISTIdentify NISTFunction = "ID-Identify"
	NISTProtect  NISTFunction = "PR-Protect"
	NISTDetect   NISTFunction = "DE-Detect"
	NISTRespond  NISTFunction = "RS-Respond"
	NISTRecover  NISTFunction = "RC-Recover"
)

// Confidence indicates how confident the scanner is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Rule defines a security check that an analyzer can perform.
type Rule struct {
	// ID is a unique identifier for this rule (e.g., "PHP-INJ-001").
	ID string

	// Title is a short human-readable name for the rule.
	Title string

	// Description explains what the rule checks for.
	Description string

	// Severity is the default severity for findings from this rule.
	Severity Severity

	// Confidence is how likely a match is a true positive.
	Confidence Confidence

	// OWASP is the OWASP Top 10:2025 category this rule maps to.
	OWASP OWASPCategory

	// NIST lists the NIST CSF 2.0 functions this rule relates to.
	NIST []NISTFunction

	// CWE is the Common Weakness Enumeration identifier (e.g., "CWE-89").
	CWE string

	// Remediation provides guidance on how to fix findings from this rule.
	Remediation string

	// References are URLs to relevant documentation.
	References []string

	// Languages lists which languages this rule applies to.
	// Empty means all languages.
	Languages []string
}

// Finding represents a single vulnerability instance detected during scanning.
type Finding struct {
	// RuleID links back to the Rule that produced this finding.
	RuleID string

	// Title is a short description of the finding.
	Title string

	// Description provides detailed context about the specific finding.
	Description string

	// Severity of this particular finding (may be adjusted from rule default).
	Severity Severity

	// Confidence of this particular finding.
	Confidence Confidence

	// FilePath is the path to the file where the finding was detected.
	FilePath string

	// Line is the 1-based line number of the finding.
	Line int

	// Column is the 1-based column number (0 if unknown).
	Column int

	// EndLine is the ending line of the finding (0 if single-line).
	EndLine int

	// Snippet is the relevant source code around the finding.
	Snippet string

	// MatchContent is the specific text that triggered the finding.
	MatchContent string

	// OWASP is the OWASP Top 10:2025 category.
	OWASP OWASPCategory

	// NIST lists the NIST CSF 2.0 functions.
	NIST []NISTFunction

	// CWE is the Common Weakness Enumeration identifier.
	CWE string

	// Remediation provides specific fix guidance for this finding.
	Remediation string

	// References are URLs to relevant documentation.
	References []string

	// Language is the language of the file where the finding was detected.
	Language string
}

// String returns a human-readable representation of the finding.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s (at %s:%d)", f.Severity, f.RuleID, f.Title, f.FilePath, f.Line)
}

// ScanReport holds the complete results of a scan operation.
type ScanReport struct {
	// ProjectPath is the root path that was scanned.
	ProjectPath string

	// ScanTimestamp is the ISO 8601 timestamp when the scan started.
	ScanTimestamp string

	// ScanDuration is the human-readable scan duration (e.g., "1.23s").
	ScanDuration string

	// ScanDurationMs is the scan duration in milliseconds.
	ScanDurationMs int64

	// TotalFiles is the number of files scanned.
	TotalFiles int

	// TotalFindings is the total number of findings.
	TotalFindings int

	// Findings is the list of all findings, sorted by severity.
	Findings []Finding

	// Summary provides aggregate counts by category.
	Summary ReportSummary

	// Languages lists the languages detected in the project.
	Languages []string

	// ScannerVersion is the version of SAMUH that produced this report.
	ScannerVersion string
}

// ReportSummary provides aggregate statistics for a scan report.
type ReportSummary struct {
	// BySeverity counts findings per severity level.
	BySeverity map[Severity]int

	// ByOWASP counts findings per OWASP category.
	ByOWASP map[OWASPCategory]int

	// ByNIST counts findings per NIST function.
	ByNIST map[NISTFunction]int

	// ByLanguage counts findings per language.
	ByLanguage map[string]int

	// ByFile counts findings per file path.
	ByFile map[string]int
}

// NewReportSummary creates a ReportSummary with initialized maps.
func NewReportSummary() ReportSummary {
	return ReportSummary{
		BySeverity: make(map[Severity]int),
		ByOWASP:    make(map[OWASPCategory]int),
		ByNIST:     make(map[NISTFunction]int),
		ByLanguage: make(map[string]int),
		ByFile:     make(map[string]int),
	}
}
