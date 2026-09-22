package reporter

import (
	"encoding/json"
	"samuh/internal/rules"
)

// SARIFReporter generates a SARIF 2.1.0 format report.
type SARIFReporter struct{}

// Format returns the format of this reporter.
func (r *SARIFReporter) Format() Format {
	return FormatSARIF
}

// severityToSarifLevel maps SAMUH severities to SARIF levels.
func severityToSarifLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow, rules.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// Generate produces the SARIF report content as bytes.
func (r *SARIFReporter) Generate(report *rules.ScanReport) ([]byte, error) {
	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "SAMUH",
						Version: report.ScannerVersion,
						Rules:   make([]sarifRule, 0),
					},
				},
				Results: make([]sarifResult, 0),
			},
		},
	}

	if doc.Runs[0].Tool.Driver.Version == "" {
		doc.Runs[0].Tool.Driver.Version = "1.0.0"
	}

	ruleMap := make(map[string]int)
	rulesList := make([]sarifRule, 0)

	for _, finding := range report.Findings {
		ruleIndex, exists := ruleMap[finding.RuleID]
		if !exists {
			ruleIndex = len(rulesList)
			ruleMap[finding.RuleID] = ruleIndex
			rulesList = append(rulesList, sarifRule{
				ID:   finding.RuleID,
				Name: finding.Title,
				ShortDescription: &sarifMessage{
					Text: finding.Title,
				},
				FullDescription: &sarifMessage{
					Text: finding.Description,
				},
				Help: &sarifMessage{
					Text: finding.Remediation,
				},
			})
		}

		result := sarifResult{
			RuleID:    finding.RuleID,
			RuleIndex: ruleIndex,
			Level:     severityToSarifLevel(finding.Severity),
			Message: sarifMessage{
				Text: finding.Description,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: finding.FilePath,
						},
						Region: sarifRegion{
							StartLine:   finding.Line,
							StartColumn: finding.Column,
						},
					},
				},
			},
		}

		if finding.EndLine > 0 {
			result.Locations[0].PhysicalLocation.Region.EndLine = finding.EndLine
		}

		doc.Runs[0].Results = append(doc.Runs[0].Results, result)
	}

	doc.Runs[0].Tool.Driver.Rules = rulesList

	return json.MarshalIndent(doc, "", "  ")
}

// FileExtension returns the file extension for SARIF reports.
func (r *SARIFReporter) FileExtension() string {
	return ".sarif"
}

// SARIF Types

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name,omitempty"`
	ShortDescription *sarifMessage `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage `json:"fullDescription,omitempty"`
	Help             *sarifMessage `json:"help,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}
