package reporter

import (
	"encoding/json"
	"samuh/internal/rules"
)

// JSONReporter outputs the scan report as pretty-printed JSON.
type JSONReporter struct{}

// Format returns the format of this reporter.
func (r *JSONReporter) Format() Format {
	return FormatJSON
}

// Generate produces the JSON report content as bytes.
func (r *JSONReporter) Generate(report *rules.ScanReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// FileExtension returns the file extension for JSON reports.
func (r *JSONReporter) FileExtension() string {
	return ".json"
}
