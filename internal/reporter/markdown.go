package reporter

import (
	"bytes"
	"fmt"
	"samuh/internal/rules"
	"strings"
)

// MarkdownReporter generates a comprehensive markdown report.
type MarkdownReporter struct{}

// Format returns the format of this reporter.
func (r *MarkdownReporter) Format() Format {
	return FormatMarkdown
}

// severityEmoji maps severities to emojis.
func severityEmoji(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "🔴 CRITICAL"
	case rules.SeverityHigh:
		return "🟠 HIGH"
	case rules.SeverityMedium:
		return "🟡 MEDIUM"
	case rules.SeverityLow:
		return "🔵 LOW"
	case rules.SeverityInfo:
		return "⚪ INFO"
	default:
		return string(s)
	}
}

// Generate produces the markdown report content as bytes.
func (r *MarkdownReporter) Generate(report *rules.ScanReport) ([]byte, error) {
	var buf bytes.Buffer

	// Title
	buf.WriteString("# 🛡️ SAMUH Security Scan Report\n\n")

	// Summary
	buf.WriteString("## Summary\n")
	buf.WriteString(fmt.Sprintf("- **Project:** %s\n", report.ProjectPath))
	buf.WriteString(fmt.Sprintf("- **Scan Date:** %s\n", report.ScanTimestamp))
	buf.WriteString(fmt.Sprintf("- **Duration:** %s\n", report.ScanDuration))
	buf.WriteString(fmt.Sprintf("- **Files Scanned:** %d\n", report.TotalFiles))
	buf.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", report.TotalFindings))
	buf.WriteString(fmt.Sprintf("- **Languages:** %s\n\n", strings.Join(report.Languages, ", ")))

	// Findings by Severity
	buf.WriteString("### Findings by Severity\n")
	buf.WriteString("| Severity | Count |\n|----------|-------|\n")
	severities := []rules.Severity{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow, rules.SeverityInfo}
	for _, s := range severities {
		if count, ok := report.Summary.BySeverity[s]; ok && count > 0 {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", severityEmoji(s), count))
		}
	}
	buf.WriteString("\n")

	// OWASP Top 10 Coverage
	buf.WriteString("### OWASP Top 10:2025 Coverage\n")
	buf.WriteString("| Category | Findings |\n|----------|----------|\n")
	for owasp, count := range report.Summary.ByOWASP {
		if count > 0 {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", string(owasp), count))
		}
	}
	buf.WriteString("\n")

	// Findings Section
	buf.WriteString("## Findings\n\n")

	// Group findings by severity
	findingsBySeverity := make(map[rules.Severity][]rules.Finding)
	for _, f := range report.Findings {
		findingsBySeverity[f.Severity] = append(findingsBySeverity[f.Severity], f)
	}

	for _, s := range severities {
		if findings, ok := findingsBySeverity[s]; ok && len(findings) > 0 {
			buf.WriteString(fmt.Sprintf("### %s\n\n", severityEmoji(s)))

			for i, f := range findings {
				buf.WriteString(fmt.Sprintf("#### %d. %s\n", i+1, f.Title))
				buf.WriteString(fmt.Sprintf("- **Rule:** %s\n", f.RuleID))
				buf.WriteString(fmt.Sprintf("- **File:** %s:%d\n", f.FilePath, f.Line))
				if f.OWASP != "" {
					buf.WriteString(fmt.Sprintf("- **OWASP:** %s\n", f.OWASP))
				}
				if len(f.NIST) > 0 {
					nistStrings := make([]string, len(f.NIST))
					for j, n := range f.NIST {
						nistStrings[j] = string(n)
					}
					buf.WriteString(fmt.Sprintf("- **NIST:** %s\n", strings.Join(nistStrings, ", ")))
				}
				if f.CWE != "" {
					buf.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
				}
				buf.WriteString(fmt.Sprintf("- **Confidence:** %s\n\n", string(f.Confidence)))
				
				if f.Description != "" {
					buf.WriteString(f.Description + "\n\n")
				}

				if f.Snippet != "" {
					buf.WriteString("**Code:**\n")
					// Try to use the language for syntax highlighting if known
					lang := strings.ToLower(f.Language)
					if lang == "" {
						lang = "text"
					}
					buf.WriteString(fmt.Sprintf("```%s\n%s\n```\n\n", lang, f.Snippet))
				}

				if f.Remediation != "" {
					buf.WriteString("**Remediation:**\n")
					buf.WriteString(f.Remediation + "\n\n")
				}

				if len(f.References) > 0 {
					buf.WriteString("**References:**\n")
					for _, ref := range f.References {
						buf.WriteString(fmt.Sprintf("- %s\n", ref))
					}
					buf.WriteString("\n")
				}
				buf.WriteString("---\n\n")
			}
		}
	}

	return buf.Bytes(), nil
}

// FileExtension returns the file extension for markdown reports.
func (r *MarkdownReporter) FileExtension() string {
	return ".md"
}
