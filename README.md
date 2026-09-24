# 🛡️ SAMUH — Secure Application Makes U Happy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)

**SAMUH** is a fast, lightweight, open-source CLI security scanner for **PHP**, **Node.js**, and **JavaScript/TypeScript** projects. It detects vulnerabilities mapped to [OWASP Top 10:2025](https://owasp.org/Top10/) and [NIST CSF 2.0](https://www.nist.gov/cyberframework), generating detailed reports with actionable remediation guidance.

## ✨ Features

- **Multi-language scanning** — PHP, Node.js, JavaScript, TypeScript (React, Vue, Angular, Svelte)
- **75+ vulnerability patterns** — covering all 10 OWASP Top 10:2025 categories
- **NIST CSF 2.0 mapping** — every finding linked to Govern, Identify, Protect, Detect, Respond, or Recover
- **4 report formats** — Markdown (default), JSON, HTML (standalone with dark mode), SARIF (CI/CD)
- **CI/CD friendly** — exits with code `1` on critical/high findings, `0` otherwise
- **Concurrent scanning** — worker pool scales to all CPU cores
- **Secure by design** — no `os/exec`, no external tools, HTML reports auto-escaped, path traversal protected
- **Extensible** — add new languages or rules without modifying existing code

## 📦 Installation

### Build from Source

```bash
git clone <repository-url>
cd SAMUH
go build -o samuh .
```

### With Version Info (Recommended)

```bash
go build -ldflags "-X samuh/cmd.Version=1.0.0 -X samuh/cmd.Commit=$(git rev-parse --short HEAD) -X samuh/cmd.Date=$(date -u +%Y-%m-%d)" -o samuh .
```

## 🚀 Quick Start

```bash
# Scan the current directory
./samuh scan .

# Scan a specific project
./samuh scan /path/to/your/project

# Generate an HTML report
./samuh scan ./myapp --format html --output report.html

# Only show high and critical findings
./samuh scan ./myapp --severity high

# Scan only PHP files
./samuh scan ./myapp --language PHP

# Generate SARIF for GitHub Code Scanning
./samuh scan ./myapp --format sarif --output results.sarif
```

### Example Output

```
🛡️  SAMUH — Scanning ./myapp ...
📄 Report written to report.html
✅ Scan completed in 0.42s
📊 Found 33 finding(s) across 12 file(s)
🔴 5 CRITICAL
🟠 15 HIGH
```

The default Markdown report looks like this:

```markdown
# 🛡️ SAMUH Security Scan Report

## Summary
- **Project:** ./myapp
- **Files Scanned:** 12
- **Total Findings:** 33

### Findings by Severity
| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 15 |
| 🟡 MEDIUM | 9 |
| 🔵 LOW | 4 |

## Findings

### 🔴 CRITICAL

#### 1. SQL Injection via String Concatenation
- **Rule:** PHP-A05-001
- **File:** src/database.php:42
- **OWASP:** A05:2025-Injection
- **CWE:** CWE-89

  $query = "SELECT * FROM users WHERE id = " . $_GET['id'];

**Remediation:** Use prepared statements with parameterized queries...
```

## 📋 CLI Reference

```
samuh scan [path] [flags]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `markdown` | Report format: `json`, `html`, `markdown`, `sarif` |
| `--output` | `-o` | *(stdout)* | Output file path |
| `--severity` | `-s` | `low` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--language` | `-l` | *(all)* | Filter to specific language(s), comma-separated |
| `--exclude` | `-e` | *(none)* | Glob patterns to exclude files/directories |
| `--max-file-size` | | `1048576` | Max file size in bytes (capped at 10MB) |
| `--no-color` | | `false` | Disable colored output |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--quiet` | `-q` | `false` | Suppress all output except errors |

### Other Commands

```bash
samuh version     # Show version, commit hash, build date
samuh help        # Show help
samuh scan --help # Show scan command help
```

## 🔍 What It Detects

### OWASP Top 10:2025 Coverage

| Category | Examples |
|---|---|
| **A01** Broken Access Control | Missing auth, CORS wildcards, directory traversal, SSRF |
| **A02** Security Misconfiguration | Debug mode, verbose errors, missing security headers |
| **A03** Supply Chain Failures | Outdated deps, missing lockfiles, wildcard versions |
| **A04** Cryptographic Failures | Hardcoded secrets, MD5/SHA1 for passwords, weak random |
| **A05** Injection | SQL injection, XSS, command injection, eval(), template injection |
| **A06** Insecure Design | Missing CSRF tokens, no rate limiting |
| **A07** Auth Failures | Plaintext passwords, insecure sessions, tokens in localStorage |
| **A08** Data Integrity | Insecure deserialization, prototype pollution, unsafe eval |
| **A09** Logging Failures | Secrets in logs, missing auth event logging |
| **A10** Exception Handling | Empty catch blocks, leaked stack traces, swallowed errors |

### Supported Languages & File Types

| Language | Extensions |
|---|---|
| PHP | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` |
| Node.js | `.js`, `.mjs`, `.cjs` (server-side patterns) |
| JavaScript/TypeScript | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.vue`, `.svelte` |

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    ./samuh scan . --format sarif --output results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No critical or high findings |
| `1` | Critical or high findings detected |

## 🏗️ Architecture

SAMUH uses a modular architecture with a plugin-style analyzer registry. Adding new languages requires zero changes to existing code — just implement the `Analyzer` interface and add a blank import.

See [TECHMANUAL.md](TECHMANUAL.md) for full architecture documentation, including:
- System design with diagrams
- Concurrency model
- Security model
- How to add new languages
- How to add new vulnerability rules

## 📄 License

MIT — see [LICENSE](LICENSE).
