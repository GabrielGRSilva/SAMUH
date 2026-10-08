# 🛡️ SAMUH — Secure Application Makes U Happy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)

**SAMUH** is a command-line tool that scans your code for security problems. It works with **PHP**, **Node.js**, and **JavaScript/TypeScript** projects — and it tells you exactly what's wrong, where, and how to fix it.

Every issue it finds is mapped to real-world security standards ([OWASP Top 10:2025](https://owasp.org/Top10/) and [NIST CSF 2.0](https://www.nist.gov/cyberframework)), so you and your team know exactly what kind of risk each problem represents.

---

**Note on Project Scope:** SAMUH was developed as a Proof of Concept (PoC) and Applied Security Laboratory. Its primary goal is to explore Go concurrency patterns, CLI architecture, and vulnerability classification (OWASP/NIST) in a high-performance environment. While fully functional for its defined scope, it is an experimental tool rather than a replacement for enterprise SAST solutions.

## 📖 Table of Contents

- [What Does SAMUH Actually Do?](#-what-does-samuh-actually-do)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Understanding the Output](#-understanding-the-output)
- [All Available Flags (Explained)](#-all-available-flags-explained)
- [Report Formats](#-report-formats)
- [What Can It Detect?](#-what-can-it-detect)
- [Using SAMUH in GitHub Actions](#-using-samuh-in-github-actions)
- [Frequently Asked Questions](#-frequently-asked-questions)
- [License](#-license)

---

## 🔍 What Does SAMUH Actually Do?

When you run SAMUH against your project, it:

1. **Walks through every file** in your project directory
2. **Skips things it shouldn't scan** (binary files, `node_modules/`, `.git/`, etc.)
3. **Reads each source file line by line** and checks it against 75+ known vulnerability patterns
4. **Generates a report** listing every problem found, with:
   - What the problem is (e.g., "SQL Injection")
   - Where it is (file name + line number)
   - Why it's dangerous (OWASP/NIST classification)
   - How to fix it (specific remediation steps)

**It does NOT run your code.** It only reads the text of your source files. It's completely safe to use.

---

## 📦 Installation

### Prerequisites

You need **Go 1.26 or newer** installed. To check:

```bash
go version
# Should print something like: go version go1.26.0 windows/amd64
```

If you don't have Go, download it from [go.dev/dl](https://go.dev/dl/).

### Step 1: Get the Code

```bash
git clone <your-repository-url>
cd SecScanner
```

### Step 2: Build the Binary

**On Windows:**
```bash
go build -o samuh.exe .
```

**On macOS/Linux:**
```bash
go build -o samuh .
```

That's it! You now have a `samuh` (or `samuh.exe`) binary in your project folder. You can move it anywhere you like, or add it to your system's PATH.

### Optional: Build With Version Info

If you want the `samuh version` command to show useful info (recommended for teams):

```bash
go build -ldflags "-X samuh/cmd.Version=1.0.0 -X samuh/cmd.Commit=$(git rev-parse --short HEAD) -X samuh/cmd.Date=$(date -u +%Y-%m-%d)" -o samuh .
```

> **What are ldflags?** They're a Go build feature that lets you "bake in" values at compile time. The command above stamps the version number, git commit, and build date into the binary so `samuh version` can display them.

---

## 🚀 Quick Start

### Scan the current folder

```bash
samuh scan .
```

### Scan a specific project

```bash
samuh scan /path/to/your/project
```

### Save the report to a file

```bash
samuh scan /path/to/project --output report.md
```

### Generate a pretty HTML report

```bash
samuh scan /path/to/project --format html --output report.html
```

Then open `report.html` in your browser — it includes a dark/light theme toggle, collapsible sections, and severity filters.

---

## 📊 Understanding the Output

When you run SAMUH, you'll see something like this in your terminal:

```
🛡️  SAMUH — Scanning ./my-app ...
📄 Report written to report.md
✅ Scan completed in 0.41s
📊 Found 38 finding(s) across 3 file(s)
🔴 7 CRITICAL
🟠 16 HIGH
```

Here's what each part means:

| Output | Meaning |
|---|---|
| `🛡️ SAMUH — Scanning ...` | The scan has started |
| `📄 Report written to ...` | Your report file was saved (only if you used `--output`) |
| `✅ Scan completed in 0.41s` | How long the scan took |
| `📊 Found 38 finding(s)` | Total number of security issues found |
| `🔴 7 CRITICAL` | Issues that need to be fixed **immediately** |
| `🟠 16 HIGH` | Serious issues that should be fixed **soon** |

### Severity Levels

SAMUH classifies every finding into one of these levels:

| Level | Emoji | What It Means | Priority |
|---|---|---|---|
| **CRITICAL** | 🔴 | Directly exploitable. An attacker could use this right now. | Fix immediately |
| **HIGH** | 🟠 | Serious security weakness. Likely exploitable under common conditions. | Fix this week |
| **MEDIUM** | 🟡 | Potential vulnerability that needs certain conditions to exploit. | Plan a fix |
| **LOW** | 🔵 | Minor issue or best-practice violation. Low risk on its own. | Fix when convenient |
| **INFO** | ⚪ | Informational note. Not a vulnerability, but worth knowing about. | Optional |

### Exit Codes (Important for CI/CD)

| Exit Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings — your code passed |
| `1` | At least one CRITICAL or HIGH finding exists — your code failed |

This means you can use SAMUH in CI/CD pipelines and it will automatically fail the build if serious issues are found.

---

## 🎛️ All Available Flags (Explained)

### `samuh scan [path] [flags]`

The `scan` command is the main command. The `[path]` is optional — if you don't provide one, it scans the current directory (`.`).

#### `--format` or `-f` (default: `markdown`)

**What it does:** Chooses the output format for the report.

```bash
# Get a human-readable markdown report (the default)
samuh scan . --format markdown

# Get machine-readable JSON (good for scripting)
samuh scan . --format json

# Get a beautiful standalone HTML page
samuh scan . --format html

# Get SARIF format (for GitHub Code Scanning integration)
samuh scan . --format sarif
```

#### `--output` or `-o` (default: prints to terminal)

**What it does:** Saves the report to a file instead of printing it to the terminal.

```bash
# Without --output: prints the entire report to your terminal
samuh scan .

# With --output: saves to a file, only shows the summary in terminal
samuh scan . --output report.md
samuh scan . --format html --output report.html
```

#### `--severity` or `-s` (default: `low`)

**What it does:** Filters out findings below a certain severity level. Only findings at that level or higher will appear in the report.

```bash
# Show everything from LOW and up (default behavior)
samuh scan . --severity low

# Only show MEDIUM, HIGH, and CRITICAL findings
samuh scan . --severity medium

# Only show HIGH and CRITICAL findings
samuh scan . --severity high

# Only show CRITICAL findings
samuh scan . --severity critical

# Show absolutely everything, including INFO notes
samuh scan . --severity info
```

#### `--language` or `-l`

**What it does:** Forces SAMUH to only use specific language analyzers. By default, all analyzers run on every file they recognize. This flag lets you narrow it down.

```bash
# Only scan with the PHP analyzer
samuh scan . --language PHP

# Only scan with PHP and Node.js analyzers
samuh scan . --language PHP,Node.js

# Only scan JavaScript/TypeScript files
samuh scan . --language "JavaScript/TypeScript"
```

> **Tip:** The language names must match the analyzer names exactly: `PHP`, `Node.js`, `JavaScript/TypeScript`.

#### `--exclude` or `-e`

**What it does:** Skips files or directories matching the given glob pattern(s). Useful if you want to ignore certain files, like test fixtures or generated code.

```bash
# Skip all test files
samuh scan . --exclude "*.test.js"

# Skip multiple patterns
samuh scan . --exclude "*.test.js" --exclude "*.spec.ts"

# Skip a specific directory's files
samuh scan . --exclude "generated/*"
```

#### `--verbose` or `-v`

**What it does:** Shows you detailed information about what SAMUH is doing during the scan. This is helpful for debugging or understanding why certain files aren't being scanned.

```bash
samuh scan . --verbose
```

Example verbose output:
```
🛡️  SAMUH — Scanning . ...
[verbose] Discovered 3 file(s) to scan
[verbose] Active analyzers: JavaScript/TypeScript, Node.js, PHP
[verbose] Worker pool size: 16
[verbose] Running project-level analysis...
[verbose] PHP project analysis: 1 finding(s)
[verbose] Total raw findings before filtering: 38
[verbose] Minimum severity filter: LOW
[verbose] Findings after severity filter: 38
✅ Scan completed in 0.41s
📊 Found 38 finding(s) across 3 file(s)
```

This tells you:
- How many files were discovered
- Which analyzers are active
- How many CPU workers are processing files in parallel
- How many findings existed before and after severity filtering

#### `--quiet` or `-q`

**What it does:** The opposite of `--verbose`. Suppresses all progress messages. Only the report itself is output. Useful in CI/CD pipelines where you only want the report file.

```bash
# No emoji, no progress — just write the report
samuh scan . --quiet --output report.json --format json
```

#### `--max-file-size` (default: `1048576` = 1 MB)

**What it does:** Sets the maximum file size (in bytes) that SAMUH will scan. Files larger than this are skipped. The maximum allowed value is 10 MB (10485760 bytes).

```bash
# Scan files up to 5 MB
samuh scan . --max-file-size 5242880
```

> **Why does this exist?** Very large files take a long time to scan and are often auto-generated (like minified JavaScript bundles), where security scanning is not useful.

#### `--no-color`

**What it does:** Currently registered as a flag for future use. Intended to disable colored/emoji output for terminals that don't support Unicode.

---

### Other Commands

```bash
# Show version, commit hash, and build date
samuh version

# Show help for any command
samuh help
samuh scan --help
```

---

## 📝 Report Formats

### Markdown (default)

A human-readable `.md` file with tables, code snippets, and severity icons. Great for reading in GitHub, VS Code, or any text editor.

### JSON

A structured `.json` file containing the full scan report. Perfect for scripting, post-processing, or feeding into other tools.

### HTML

A **standalone single-file** `.html` report — no internet connection required. Features:
- Dark/light theme toggle
- Collapsible finding details
- Severity-colored badges
- Filter by severity or OWASP category
- Works on mobile

### SARIF

[SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) version 2.1.0. This is the format GitHub Code Scanning uses, so you can upload it directly:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 🔍 What Can It Detect?

SAMUH covers all **10 categories** of the OWASP Top 10:2025:

| # | Category | Example Detections |
|---|---|---|
| A01 | **Broken Access Control** | Missing auth checks, CORS `*` wildcards, directory traversal, SSRF |
| A02 | **Security Misconfiguration** | Debug mode on, verbose error messages, missing security headers |
| A03 | **Supply Chain Failures** | Outdated deps, missing lockfiles, wildcard version `"*"` in package.json |
| A04 | **Cryptographic Failures** | Hardcoded API keys, MD5/SHA1 for passwords, `Math.random()` for tokens |
| A05 | **Injection** | SQL injection, XSS (`innerHTML`, `echo $_GET`), command injection, `eval()` |
| A06 | **Insecure Design** | Missing CSRF tokens, no rate limiting |
| A07 | **Auth Failures** | Plaintext passwords, tokens in localStorage, insecure session config |
| A08 | **Data Integrity** | `unserialize()` on user input, prototype pollution, unsafe `eval()` |
| A09 | **Logging Failures** | Passwords written to logs, missing auth event logging |
| A10 | **Exception Handling** | Empty `catch {}` blocks, leaked stack traces, swallowed errors |

**Known Limitations: ** SAMUH uses highly optimized regex and line-by-line pattern matching. Because it does not perform Abstract Syntax Tree (AST) parsing or data-flow (taint) analysis, it cannot verify if user input actually reaches a vulnerable sink. This means it may flag safe code (False Positives) or miss complex, multi-file execution paths (False Negatives).

### Supported Languages & File Types

| Language | Scanned Extensions |
|---|---|
| **PHP** | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps` |
| **Node.js** | `.js`, `.mjs`, `.cjs` (server-side patterns only) |
| **JavaScript/TypeScript** | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.vue`, `.svelte` |

> **Why do .js files get scanned twice?** The Node.js analyzer looks for server-side patterns (Express, `require()`, `child_process`), while the JavaScript/TypeScript analyzer looks for client-side patterns (DOM manipulation, `localStorage`, React/Vue/Angular). If a `.js` file doesn't look like Node.js code, the Node analyzer automatically skips it.

---

## 🤖 Using SAMUH in GitHub Actions

Here's a complete workflow you can copy into your repository:

### Basic: Fail the build if security issues are found

Create a file at `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      # 1. Check out your code
      - uses: actions/checkout@v4

      # 2. Set up Go (needed to build SAMUH)
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      # 3. Build SAMUH from source
      #    (Replace with your actual repo URL)
      - name: Build SAMUH
        run: |
          git clone <your-samuh-repo-url> /tmp/samuh
          cd /tmp/samuh
          go build -o /usr/local/bin/samuh .

      # 4. Run the scan
      #    Exit code 1 = CRITICAL or HIGH findings = build fails
      - name: Run SAMUH Security Scan
        run: samuh scan . --format markdown --output security-report.md

      # 5. Upload the report as a build artifact
      #    (You can download it from the Actions tab)
      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.md
```

### Advanced: Upload results to GitHub Code Scanning

This makes findings appear directly in the "Security" tab of your GitHub repo:

```yaml
name: Security Scan (SARIF)

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Build SAMUH
        run: |
          git clone <your-samuh-repo-url> /tmp/samuh
          cd /tmp/samuh
          go build -o /usr/local/bin/samuh .

      - name: Run SAMUH Scan
        run: samuh scan . --format sarif --output results.sarif
        continue-on-error: true  # Don't fail here — let the SARIF upload handle it

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

> **What does `continue-on-error: true` do?** SAMUH exits with code `1` when it finds CRITICAL or HIGH issues, which would normally stop the workflow. `continue-on-error` lets the next step (SARIF upload) run anyway, so the results still get uploaded to GitHub's Security tab.

---

## ❓ Frequently Asked Questions

**Q: Does SAMUH run my code?**
No. It only reads the text of your source files. It never executes, compiles, or imports anything.

**Q: Will it work on private/proprietary code?**
Yes. SAMUH runs entirely on your machine. It never sends your code anywhere — there are no network calls.

**Q: Can I add support for Python / Go / Ruby / etc.?**
Yes! SAMUH is designed for extensibility. See [TECHMANUAL.md](TECHMANUAL.md) for a step-by-step guide on adding a new language analyzer.

**Q: Why does SAMUH skip `node_modules/` and `vendor/`?**
These folders contain third-party code you don't control. Scanning them would produce thousands of findings you can't fix. Use dedicated dependency scanning tools (like `npm audit` or Dependabot) for those.

**Q: How is this different from ESLint or PHPStan?**
SAMUH is specifically focused on **security vulnerabilities** (not code quality or style). It maps every finding to OWASP and NIST standards, and generates reports suitable for security audits.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🏗️ Architecture

See [TECHMANUAL.md](TECHMANUAL.md) for detailed architecture documentation.
