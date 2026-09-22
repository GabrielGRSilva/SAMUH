package javascript

import (
	"context"
	"strings"

	"samuh/internal/analyzer"
	"samuh/internal/rules"
)

func init() {
	analyzer.RegisterDefault(New())
}

// JavaScriptAnalyzer analyzes JavaScript and TypeScript files for security vulnerabilities.
type JavaScriptAnalyzer struct{}

// New creates a new JavaScriptAnalyzer.
func New() *JavaScriptAnalyzer {
	return &JavaScriptAnalyzer{}
}

// Name returns the name of the analyzer.
func (a *JavaScriptAnalyzer) Name() string {
	return "JavaScript/TypeScript"
}

// Extensions returns the file extensions supported by this analyzer.
func (a *JavaScriptAnalyzer) Extensions() []string {
	return []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
}

// Analyze scans a single JavaScript/TypeScript file for vulnerabilities.
func (a *JavaScriptAnalyzer) Analyze(ctx context.Context, file analyzer.FileContext) ([]rules.Finding, error) {
	var findings []rules.Finding

	for i, line := range file.Lines {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineStr := strings.TrimSpace(line)
		if lineStr == "" {
			continue
		}

		for _, p := range jsPatterns {
			if p.regex.MatchString(lineStr) {
				finding := rules.Finding{
					RuleID:       p.rule.ID,
					Title:        p.rule.Title,
					Description:  p.rule.Description,
					Severity:     p.rule.Severity,
					Confidence:   p.rule.Confidence,
					FilePath:     file.Path,
					Line:         i + 1, // 1-based line numbers
					Snippet:      lineStr,
					MatchContent: p.regex.FindString(lineStr),
					OWASP:        p.rule.OWASP,
					NIST:         p.rule.NIST,
					CWE:          p.rule.CWE,
					Remediation:  p.rule.Remediation,
					References:   p.rule.References,
					Language:     "JavaScript/TypeScript",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// AnalyzeProject performs project-level analysis. For JS/TS, package-level
// dependency checks are handled by the Node.js analyzer.
func (a *JavaScriptAnalyzer) AnalyzeProject(ctx context.Context, projectRoot string) ([]rules.Finding, error) {
	return nil, nil
}
