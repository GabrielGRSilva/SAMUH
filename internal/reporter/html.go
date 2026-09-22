package reporter

import (
	"bytes"
	"fmt"
	"html/template"
	"samuh/internal/rules"
)

// HTMLReporter generates a standalone HTML report.
type HTMLReporter struct{}

// Format returns the format of this reporter.
func (r *HTMLReporter) Format() Format {
	return FormatHTML
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAMUH Security Scan Report</title>
    <style>
        :root {
            --bg-color: #f8f9fa;
            --text-color: #333;
            --card-bg: #fff;
            --border-color: #dee2e6;
            --header-bg: #343a40;
            --header-text: #fff;
            --primary: #007bff;
            
            /* Severities */
            --sev-critical: #dc3545;
            --sev-high: #fd7e14;
            --sev-medium: #ffc107;
            --sev-low: #17a2b8;
            --sev-info: #6c757d;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-color: #121212;
                --text-color: #e0e0e0;
                --card-bg: #1e1e1e;
                --border-color: #333;
                --header-bg: #222;
                --header-text: #fff;
                --primary: #375a7f;
            }
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }

        .header {
            background-color: var(--header-bg);
            color: var(--header-text);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            margin: 0;
            font-size: 1.5rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }

        .summary-stat {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .summary-label {
            color: var(--text-color);
            opacity: 0.8;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        th, td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }

        th {
            background-color: rgba(0,0,0,0.02);
            font-weight: 600;
        }

        .badge {
            display: inline-block;
            padding: 0.25em 0.4em;
            font-size: 75%;
            font-weight: 700;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 0.25rem;
            color: #fff;
        }

        .badge-CRITICAL { background-color: var(--sev-critical); }
        .badge-HIGH { background-color: var(--sev-high); }
        .badge-MEDIUM { background-color: var(--sev-medium); color: #212529; }
        .badge-LOW { background-color: var(--sev-low); }
        .badge-INFO { background-color: var(--sev-info); }

        details {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            margin-bottom: 1rem;
        }

        summary {
            padding: 1rem;
            cursor: pointer;
            font-weight: bold;
            display: flex;
            align-items: center;
            user-select: none;
        }
        
        summary:hover {
            background-color: rgba(0,0,0,0.02);
        }

        .finding-details {
            padding: 1rem;
            border-top: 1px solid var(--border-color);
        }

        pre {
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 1rem;
            overflow-x: auto;
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.875rem;
        }
        
        @media (prefers-color-scheme: dark) {
            pre {
                background-color: #2d2d2d;
                border-color: #444;
            }
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
            background: rgba(0,0,0,0.02);
            padding: 1rem;
            border-radius: 4px;
        }

        .meta-item {
            font-size: 0.9rem;
        }
        
        .meta-label {
            font-weight: bold;
            margin-right: 0.5rem;
        }

        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-color);
            opacity: 0.7;
            font-size: 0.85rem;
        }

        input[type="text"] {
            width: 100%;
            padding: 0.5rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background-color: var(--card-bg);
            color: var(--text-color);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SAMUH Security Scanner</h1>
        <div>v{{.ScannerVersion}}</div>
    </div>

    <div class="container">
        <div class="card">
            <h2>Scan Summary</h2>
            <div class="grid">
                <div>
                    <div class="summary-stat">{{.TotalFindings}}</div>
                    <div class="summary-label">Total Findings</div>
                </div>
                <div>
                    <div class="summary-stat">{{.TotalFiles}}</div>
                    <div class="summary-label">Files Scanned</div>
                </div>
                <div>
                    <div class="summary-stat">{{.ScanDuration}}</div>
                    <div class="summary-label">Duration</div>
                </div>
                <div>
                    <div class="summary-stat">{{.ProjectPath}}</div>
                    <div class="summary-label">Project</div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Findings by Severity</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range $sev, $count := .Summary.BySeverity}}
                        <tr>
                            <td><span class="badge badge-{{$sev}}">{{$sev}}</span></td>
                            <td>{{$count}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>OWASP Top 10</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range $cat, $count := .Summary.ByOWASP}}
                        <tr>
                            <td>{{$cat}}</td>
                            <td>{{$count}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h2>Findings</h2>
            <input type="text" id="searchInput" placeholder="Filter findings by text..." onkeyup="filterFindings()">
            
            <div id="findingsList">
                {{range .Findings}}
                <details class="finding-item" data-text="{{.Title}} {{.RuleID}} {{.FilePath}} {{.Severity}} {{.OWASP}}">
                    <summary>
                        <span class="badge badge-{{.Severity}}" style="margin-right: 1rem;">{{.Severity}}</span>
                        {{.Title}} ({{.FilePath}}:{{.Line}})
                    </summary>
                    <div class="finding-details">
                        <div class="meta-grid">
                            <div class="meta-item"><span class="meta-label">Rule ID:</span> {{.RuleID}}</div>
                            <div class="meta-item"><span class="meta-label">File:</span> {{.FilePath}}:{{.Line}}</div>
                            {{if .OWASP}}<div class="meta-item"><span class="meta-label">OWASP:</span> {{.OWASP}}</div>{{end}}
                            {{if .CWE}}<div class="meta-item"><span class="meta-label">CWE:</span> {{.CWE}}</div>{{end}}
                            <div class="meta-item"><span class="meta-label">Confidence:</span> {{.Confidence}}</div>
                        </div>

                        {{if .Description}}
                        <p>{{.Description}}</p>
                        {{end}}

                        {{if .Snippet}}
                        <h4>Code Snippet</h4>
                        <pre><code>{{.Snippet}}</code></pre>
                        {{end}}

                        {{if .Remediation}}
                        <h4>Remediation</h4>
                        <p>{{.Remediation}}</p>
                        {{end}}

                        {{if .References}}
                        <h4>References</h4>
                        <ul>
                            {{range .References}}
                            <li><a href="{{.}}" target="_blank" rel="noopener noreferrer">{{.}}</a></li>
                            {{end}}
                        </ul>
                        {{end}}
                    </div>
                </details>
                {{end}}
            </div>
        </div>
    </div>

    <div class="footer">
        Generated by SAMUH on {{.ScanTimestamp}}
    </div>

    <script>
        function filterFindings() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const items = document.getElementsByClassName('finding-item');
            
            for (let i = 0; i < items.length; i++) {
                const text = items[i].getAttribute('data-text').toLowerCase();
                if (text.indexOf(filter) > -1) {
                    items[i].style.display = "";
                } else {
                    items[i].style.display = "none";
                }
            }
        }
    </script>
</body>
</html>`

// Generate produces the HTML report content as bytes.
func (r *HTMLReporter) Generate(report *rules.ScanReport) ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse html template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return nil, fmt.Errorf("failed to execute html template: %w", err)
	}

	return buf.Bytes(), nil
}

// FileExtension returns the file extension for HTML reports.
func (r *HTMLReporter) FileExtension() string {
	return ".html"
}
