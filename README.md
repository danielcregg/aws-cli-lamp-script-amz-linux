# AWS LAMP Stack Deployment Script for Amazon Linux

Automates the deployment of a LAMP stack (Linux, Apache, MariaDB, PHP) on an AWS EC2 instance running Amazon Linux 2023. The script handles all AWS resource creation, software installation, and configuration in a single command.

## Scripts

This repo contains two scripts:

| Script | Purpose |
|--------|---------|
| `lamp-aws-installer-al.sh` | **Main script** — creates AWS infrastructure (EC2, security group, key pair, Elastic IP) and deploys a LAMP stack with optional extras like WordPress and Matomo |
| `aws_cli_installer.sh` | **One-time setup helper** — installs AWS CLI v2 on your local machine, sets the default region to `eu-west-1`, and prompts you to enter your AWS credentials |

Run `aws_cli_installer.sh` first if you don't already have the AWS CLI installed, then use `lamp-aws-installer-al.sh` to deploy.

## Prerequisites

- **AWS CLI** installed and configured with valid credentials (run `aws_cli_installer.sh` or `aws configure`)
- **AWS IAM permissions** for EC2, VPC, Elastic IP, SSM parameter read, and key pair management
- **Bash** shell with `curl` and `ssh` available

## Quick Start

Run the script directly from GitHub (no clone needed):

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh)
```

By default this creates the EC2 instance and AWS resources but does not install any software. Use the flags below to choose what to install.

## Installation Options

Each flag includes everything from the previous levels:

| Flag | What gets installed |
|------|---------------------|
| `-lamp` | Apache, MariaDB, PHP, sample PHP site |
| `-sftp` | LAMP + SFTP root login |
| `-vscode` | LAMP + SFTP + VS Code Server |
| `-db` | LAMP + SFTP + VS Code + database tools |
| `-wp` | LAMP + SFTP + VS Code + DB tools + WordPress (with WP-CLI, Imagick) |
| `-mt` | Full stack: all of the above + Matomo Analytics |

### Examples

Install just the LAMP stack:

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -lamp
```

Install WordPress and all dependencies:

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -wp
```

Install the full stack including Matomo Analytics:

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -mt
```

## AWS Resources Created

The script creates and manages the following AWS resources:

| Resource | Name/Details |
|----------|-------------|
| EC2 Instance | `t2.medium`, 10 GB gp3 volume, Amazon Linux 2023 |
| Security Group | `sgWebServerAuto` — ports 22, 80, 443, 8080 open |
| Key Pair | `keyWebServerAuto` — stored at `~/.ssh/keyWebServerAuto` |
| Elastic IP | `elasticIPWebServerAuto` — reused across runs |

On subsequent runs, the script automatically cleans up previous instances and reuses existing Elastic IPs and security groups.

## Connecting to the Instance

After the script completes, connect via:

```bash
ssh vm
```

This works because the script adds a host entry to `~/.ssh/config`.

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| SFTP (root login) | `root` | `tester` |
| WordPress admin | `admin` | `password` |
| WordPress DB user | `wordpressuser` | `password` |
| Matomo DB user | `matomoadmin` | `password` |

## Security Notice

This script is intended for **development, testing, and demo purposes only**. It uses hardcoded default passwords and opens security group ports to `0.0.0.0/0`. Do not use it for production deployments without changing all credentials and restricting network access.
