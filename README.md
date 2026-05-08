# Security Guard Lite

A lightweight, zero-dependency security scanner for detecting leaked credentials in codebases.

## Features

- **3-Layer Detection Engine**: Keyword matching → Pattern matching → Entropy analysis
- **38+ Credential Types**: OpenAI, GitHub, AWS, Slack, Stripe, JWT, and more
- **Cloud Breach Check**: Optional lookup via k-Anonymity protocol (similar to Have I Been Pwned)
- **Zero Dependencies**: Pure Python standard library
- **Local-First**: All scanning happens locally; cloud features are optional

## Quick Start

```bash
# Clone the repository
git clone https://github.com/SpaceRelax/security-guard-lite.git
cd security-guard-lite

# Run a scan
python3 scripts/scanner.py /path/to/your/project
```

## Usage

### Basic Scan (Local Only)

```bash
python3 scripts/scanner.py .
```

### Enable Cloud Breach Check

Edit `references/config.yaml`:

```yaml
detection:
  cloud_lookup: true
```

Then run:

```bash
python3 scripts/scanner.py .
```

## Detection Layers

| Layer | Method | Description |
|-------|--------|-------------|
| 1 | Keyword Matching | Fast initial scan for `api_key`, `password`, `token`, `secret` |
| 2 | Pattern Matching | High-confidence regex patterns for known credential formats |
| 3 | Entropy Analysis | Identify unknown high-randomness strings (entropy > 4.5) |

## Supported Credentials

- OpenAI API Key (`sk-...`)
- GitHub Personal Access Token (`ghp_...`)
- GitHub Fine-Grained Token (`github_pat_...`)
- AWS Access Key ID (`AKIA...`)
- Slack Token (`xoxb-...`, `xoxp-...`)
- Stripe API Key (`sk_live_...`, `sk_test_...`)
- JWT Token (`eyJ...`)
- Google API Key (`AIza...`)
- MongoDB Connection String
- PostgreSQL Connection String
- MySQL Connection String
- Private Keys (RSA, EC, DSA, OpenSSH)
- And more...

## Configuration

Edit `references/config.yaml` to customize:

```yaml
detection:
  cloud_lookup: false      # Enable/disable cloud breach check
  entropy_threshold: 4.5   # Entropy detection sensitivity
  enable_layer_1: true     # Keyword matching
  enable_layer_2: true     # Pattern matching
  enable_layer_3: true     # Entropy detection

audit:
  enabled: true            # Enable/disable anonymous audit stats
  batch_size: 10           # Audit log batch size
```

## Privacy & Security

### Local Processing

All file scanning and pattern matching happen locally. No files are uploaded.

### Cloud Features (Optional)

**Breach Database Check**:
- Uses k-Anonymity protocol: sends SHA-256 prefix (first 5 chars)
- Server does not retain original credential values
- Can be disabled by setting `cloud_lookup: false`

**Anonymous Audit Stats**:
- Uploads anonymized detection statistics only
- No credential values, file paths, or identifiable information
- Used to improve detection rule accuracy
- Can be disabled by setting `audit.enabled: false`

### Run Completely Offline

```yaml
detection:
  cloud_lookup: false

audit:
  enabled: false
```

## Output

Reports are generated in Markdown format at `reports/security-report-{timestamp}.md`:

```markdown
# Security Guard Lite — Security Scan Report

**Scan Time:** 2026-05-08 10:30:00
**Target:** /path/to/project
**Findings:** 12
**Breach Hits:** 3

## Risk Overview

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 5 | Immediate action required |
| 🟠 High | 3 | Fix as soon as possible |
| 🟡 Medium | 4 | Review recommended |
```

## Project Structure

```
security-guard-lite/
├── SKILL.md                 # Skill definition with YAML frontmatter
├── README.md                # This file
├── references/
│   ├── config.yaml          # Configuration file
│   └── patterns.json        # Detection rules database
├── scripts/
│   └── scanner.py           # Main scanner script
├── assets/                  # Resource files
└── reports/                 # Generated reports
```

## Requirements

- Python 3.7+
- No external dependencies

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational and security auditing purposes only. Always ensure you have permission to scan the target codebase. The authors are not responsible for any misuse of this tool.
