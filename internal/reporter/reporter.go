// Package reporter defines the interface for report generation and provides
// factory methods for the supported output formats.
package reporter

import (
	"fmt"
	"samuh/internal/rules"
	"strings"
)

// Format represents a supported report output format.
type Format string

const (
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

// ParseFormat converts a string to a Format, returning an error for unknown formats.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON, nil
	case "html":
		return FormatHTML, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("unknown report format %q (supported: json, html, markdown, sarif)", s)
	}
}

// Reporter generates a report from scan results.
type Reporter interface {
	// Format returns the output format of this reporter.
	Format() Format

	// Generate produces the report content as bytes.
	Generate(report *rules.ScanReport) ([]byte, error)

	// FileExtension returns the appropriate file extension for the output
	// (e.g., ".json", ".html", ".md").
	FileExtension() string
}

// New creates a reporter for the specified format.
func New(format Format) (Reporter, error) {
	switch format {
	case FormatJSON:
		return &JSONReporter{}, nil
	case FormatHTML:
		return &HTMLReporter{}, nil
	case FormatMarkdown:
		return &MarkdownReporter{}, nil
	case FormatSARIF:
		return &SARIFReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}
