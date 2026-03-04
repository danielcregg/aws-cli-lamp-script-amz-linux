# CLAUDE.md — Project Guide for AI Assistants

## Project Overview

This repo contains Bash scripts that automate AWS infrastructure provisioning and LAMP stack deployment on Amazon Linux 2023 EC2 instances. It is used for **teaching and demo purposes** at ATU (Atlantic Technological University).

## Scripts

| Script | Lines | Purpose |
|--------|-------|---------|
| `lamp-aws-installer-al.sh` | ~637 | Modular LAMP installer with cumulative flags (`-lamp`, `-sftp`, `-vscode`, `-db`, `-wp`, `-mt`). Uses an Elastic IP. Used in multiple classes — **do not delete or merge into the HTTPS script**. |
| `alb-https-installer.sh` | ~856 | Standalone end-to-end WordPress + HTTPS script. Creates EC2, installs LAMP + WordPress, then configures ALB + ACM + Route 53. No flags — installs everything. No Elastic IP (instance is behind ALB). |
| `aws_cli_installer.sh` | ~48 | One-time helper that installs AWS CLI v2, sets region to `eu-west-1`, and prompts for credentials. |

## Architecture & Conventions

### Naming convention
All AWS resource names use **camelCase** with a `WebServerAuto` suffix:
- `keyWebServerAuto`, `sgWebServerAuto`, `sgAlbWebServerAuto`
- `tgWebServerAuto`, `albWebServerAuto`, `eipWebServerAuto`
- `eipAlbWebServerAuto-1a` (ALB EIPs include AZ suffix)
- Instance tag: `WebServerAuto`, Volume tag: `volWebServerAuto`

### Script style
- Bash strict mode: `set -euo pipefail` (local), `set -eo pipefail` (remote SSH)
- `export MSYS_NO_PATHCONV=1` at the top of the HTTPS script (prevents Git Bash path mangling on Windows)
- Colored output helpers: `step()`, `info()`, `ok()`, `note()`, `die()`, `spinner()`/`stop_spinner()`
- Remote (SSH) variants use parentheses: `rstep()`, `rok()`, `rinfo()`, `rnote()`, `rspin()`/`rstop()`
- Local steps use `[N]` format, remote sub-steps use `(N)` format
- `link()` creates OSC 8 clickable hyperlinks in terminal
- `open_sg_port()` is idempotent — checks for `InvalidPermission.Duplicate`

### Idempotency pattern
Every resource is checked before creation:
1. `describe-*` or `list-*` to check existence
2. If found, reuse; if not, create
3. Route 53 records use `UPSERT` (always safe to re-run)
4. Security group port rules silently skip duplicates

### Key design decisions
- **No Elastic IP in HTTPS script**: Instance is behind an ALB target group, so EIP is unnecessary. Uses auto-assigned public IP for SSH access only.
- **ACM certificate requested early** (step 4) so DNS validation proceeds in background while EC2 boots and software installs. Wait only happens at step 14 (listener creation) if cert isn't issued yet.
- **WordPress URL safety**: HTTPS is tested with `curl` before updating `siteurl`/`home`. If test fails, WP is left on HTTP with manual instructions printed.
- **ALB EIPs are tagged** after ALB creation/reuse with names like `eipAlbWebServerAuto-1a`.

## Common Modifications

### Adding a new installation step (HTTPS script)
1. Add the install commands inside the remote SSH session block (step 10, the single-quoted `ssh -t ... '...'` command)
2. Use the remote helpers (`rstep`, `rspin`, `rstop`, `rok`) for output
3. Keep the step inside the single-quoted string — no variable expansion from the local shell

### Adding a new AWS resource
1. Add a config variable at the top (follow naming convention)
2. Add a describe-before-create check (idempotency)
3. Tag with `Key=Name,Value=<resourceName>`
4. Add cleanup logic in step 1 if the resource should be destroyed on re-run

### Adding a new flag to the LAMP script
1. Add a new `INSTALL_*` variable and `case` entry in the argument parser
2. Make flags cumulative (each level enables all previous levels)
3. Add the install block inside the remote SSH session, guarded by `if [ '"$INSTALL_*"' = true ]`

## Testing

- Scripts are tested by running them against a live AWS account (region: `eu-west-1`)
- The HTTPS script prompts for a domain name and pauses for nameserver configuration — cannot be fully automated without manual DNS setup
- When testing from Windows (Git Bash), note that `curl` HTTPS verification may fail due to Schannel; use `--resolve` flag to test directly against ALB IP

## Default credentials (development only)
- SFTP root: `root` / `tester`
- WordPress admin: `admin` / `password`
- WordPress DB: `wordpressuser` / `password`
- Matomo DB (LAMP script only): `matomoadmin` / `password`

## Important warnings
- **Never delete `lamp-aws-installer-al.sh`** — it is used independently in other classes
- **Never commit AWS credentials** (`.pem` files and `credentials` are in `.gitignore`)
- These scripts open ports to `0.0.0.0/0` and use hardcoded passwords — development/demo use only
