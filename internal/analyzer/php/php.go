package php

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"samuh/internal/analyzer"
	"samuh/internal/rules"
)

func init() {
	analyzer.RegisterDefault(&PHPAnalyzer{})
}

// PHPAnalyzer is an analyzer for PHP applications.
type PHPAnalyzer struct{}

// Name returns the name of the analyzer.
func (a *PHPAnalyzer) Name() string {
	return "PHP"
}

// Extensions returns the file extensions analyzed by this analyzer.
func (a *PHPAnalyzer) Extensions() []string {
	return []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"}
}

// Analyze scans a single file line by line against the pre-compiled patterns.
func (a *PHPAnalyzer) Analyze(ctx context.Context, file analyzer.FileContext) ([]rules.Finding, error) {
	var findings []rules.Finding

	for i, line := range file.Lines {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum := i + 1

		for _, pat := range vulnerabilityPatterns {
			if matches := pat.Regex.FindStringIndex(line); matches != nil {
				start := matches[0]
				end := matches[1]

				// Extract snippet (up to 3 lines of context)
				snippetStart := i - 1
				if snippetStart < 0 {
					snippetStart = 0
				}
				snippetEnd := i + 2
				if snippetEnd > len(file.Lines) {
					snippetEnd = len(file.Lines)
				}
				snippetLines := file.Lines[snippetStart:snippetEnd]
				snippet := strings.Join(snippetLines, "\n")

				finding := rules.Finding{
					RuleID:       pat.Rule.ID,
					Title:        pat.Rule.Title,
					Description:  pat.Rule.Description,
					Severity:     pat.Rule.Severity,
					Confidence:   pat.Rule.Confidence,
					FilePath:     file.Path, // Assuming absolute path; usually RelativePath is preferred in reporting but we provide Path
					Line:         lineNum,
					Column:       start + 1, // 1-based column
					EndLine:      lineNum,
					Snippet:      snippet,
					MatchContent: line[start:end],
					OWASP:        pat.Rule.OWASP,
					NIST:         pat.Rule.NIST,
					CWE:          pat.Rule.CWE,
					Remediation:  pat.Rule.Remediation,
					References:   pat.Rule.References,
					Language:     "PHP",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// AnalyzeProject performs project-level checks, such as examining composer.json
// and composer.lock for Software Supply Chain issues (A03).
func (a *PHPAnalyzer) AnalyzeProject(ctx context.Context, projectRoot string) ([]rules.Finding, error) {
	var findings []rules.Finding

	composerJsonPath := filepath.Join(projectRoot, "composer.json")
	composerLockPath := filepath.Join(projectRoot, "composer.lock")

	_, errLock := os.Stat(composerLockPath)
	if os.IsNotExist(errLock) {
		findings = append(findings, rules.Finding{
			RuleID:      "PHP-A03-001",
			Title:       "Missing composer.lock",
			Description: "The project is missing a composer.lock file. This can lead to unrepeatable builds and unexpected supply chain vulnerabilities.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			FilePath:    projectRoot,
			OWASP:       rules.OWASPA03,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1104",
			Remediation: "Commit the composer.lock file to your version control system.",
			Language:    "PHP",
		})
	}

	jsonBytes, err := os.ReadFile(composerJsonPath)
	if err == nil {
		var composerData struct {
			MinimumStability string `json:"minimum-stability"`
		}
		if err := json.Unmarshal(jsonBytes, &composerData); err == nil {
			stability := strings.ToLower(composerData.MinimumStability)
			if stability == "dev" || stability == "alpha" || stability == "beta" {
				findings = append(findings, rules.Finding{
					RuleID:      "PHP-A03-002",
					Title:       "Insecure Minimum Stability",
					Description: "The minimum-stability in composer.json is set to a pre-release level (dev/alpha/beta), which may introduce unstable or vulnerable packages.",
					Severity:    rules.SeverityMedium,
					Confidence:  rules.ConfidenceHigh,
					FilePath:    composerJsonPath,
					OWASP:       rules.OWASPA03,
					NIST:        []rules.NISTFunction{rules.NISTProtect},
					CWE:         "CWE-1035",
					Remediation: "Change minimum-stability to 'stable' or use explicit version constraints for specific development packages.",
					Language:    "PHP",
				})
			}
		}
	} else if !os.IsNotExist(err) && !isPathError(err) {
		// Log error somewhere, but ignoring for now per standard scanner behaviour
	}

	return findings, nil
}

func isPathError(err error) bool {
	_, ok := err.(*fs.PathError)
	return ok
}
