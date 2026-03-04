# AWS LAMP Stack Deployment Script for Amazon Linux

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat-square&logo=amazonwebservices&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

Single-command automation scripts that provision AWS infrastructure and deploy web servers on Amazon Linux 2023 EC2 instances.

## Overview

This project contains three Bash scripts that streamline the process of standing up a web server on AWS.

| Script | Purpose |
|--------|---------|
| `lamp-aws-installer-al.sh` | **LAMP script** -- creates AWS infrastructure (EC2, security group, key pair, Elastic IP) and deploys a LAMP stack with optional extras like WordPress and Matomo |
| `alb-https-installer.sh` | **WordPress + HTTPS script** -- standalone end-to-end script that creates all AWS infrastructure, installs LAMP + WordPress, and configures HTTPS via an ALB with ACM certificate and Route 53 DNS |
| `aws_cli_installer.sh` | **One-time setup helper** -- installs AWS CLI v2 on your local machine, sets the default region to `eu-west-1`, and prompts you to enter your AWS credentials |

## Features

- Fully automated EC2 instance provisioning with Amazon Linux 2023
- Cumulative installation flags for modular deployment (`-lamp`, `-sftp`, `-vscode`, `-db`, `-wp`, `-mt`)
- Automatic cleanup of previous instances on re-run
- Elastic IP reuse across deployments
- SSH key pair management with local `~/.ssh/config` setup
- WordPress installation with WP-CLI, Imagick, and database configuration
- Matomo Analytics integration with WordPress plugins
- HTTPS via Application Load Balancer with ACM certificate and Route 53 DNS
- Retry logic with exponential backoff for key AWS operations
- Color-coded terminal output with progress spinners

## Prerequisites

- **AWS CLI** installed and configured with valid credentials (run `aws_cli_installer.sh` or `aws configure`)
- **AWS IAM permissions** for EC2, VPC, Elastic IP, SSM parameter read, and key pair management (the WordPress + HTTPS script additionally requires Route 53, ACM, and Elastic Load Balancing permissions)
- **Bash** shell with `curl`, `unzip`, and `ssh` available

## Getting Started

### Installation

Run the script directly from GitHub (no clone needed):

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh)
```

If you do not have the AWS CLI installed, run the helper script first:

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/aws_cli_installer.sh)
```

### Usage

Each flag includes everything from the previous levels:

| Flag | What Gets Installed |
|------|---------------------|
| `-lamp` | Apache, MariaDB, PHP, sample PHP site |
| `-sftp` | LAMP + SFTP root login |
| `-vscode` | LAMP + SFTP + VS Code Server |
| `-db` | LAMP + SFTP + VS Code + database tools |
| `-wp` | LAMP + SFTP + VS Code + DB tools + WordPress (with WP-CLI, Imagick) |
| `-mt` | Full stack: all of the above + Matomo Analytics |

**Install just the LAMP stack:**

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -lamp
```

**Install WordPress and all dependencies:**

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -wp
```

**Install the full stack including Matomo Analytics:**

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/lamp-aws-installer-al.sh) -mt
```

### WordPress + HTTPS (standalone)

Deploy WordPress with HTTPS in a single command — no need to run the LAMP script first:

```bash
bash <(curl -sL https://raw.githubusercontent.com/danielcregg/aws-cli-lamp-script-amz-linux/refs/heads/main/alb-https-installer.sh)
```

This script creates all infrastructure from scratch, installs LAMP + WordPress, then configures an ALB with an ACM TLS certificate and Route 53 DNS. It will prompt for your domain name and pause while you configure your registrar's nameservers.

### Connecting to the Instance

After the script completes, connect via:

```bash
ssh vm
```

This works because the script adds a host entry to `~/.ssh/config`.

## AWS Resources Created

| Resource | Name / Details |
|----------|----------------|
| EC2 Instance | `t2.medium`, 10 GB gp3 volume, Amazon Linux 2023 |
| Security Group | `sgWebServerAuto` -- ports 22, 80, 443, 8080 open |
| Key Pair | `keyWebServerAuto` -- stored at `~/.ssh/keyWebServerAuto` |
| Elastic IP | `eipWebServerAuto` -- reused across runs (LAMP script only) |
| ALB | `albWebServerAuto` -- internet-facing, HTTPS termination (HTTPS script only) |
| ALB Security Group | `sgAlbWebServerAuto` -- ports 80, 443 open (HTTPS script only) |
| ALB Elastic IPs | `eipAlbWebServerAuto-1a`, `-1b`, `-1c` -- one per availability zone (HTTPS script only) |
| Target Group | `tgWebServerAuto` -- HTTP:80, health check on `/` (HTTPS script only) |
| ACM Certificate | DNS-validated TLS certificate for your domain (HTTPS script only) |
| Route 53 Hosted Zone | DNS zone with NS, A (alias to ALB), and validation CNAME records (HTTPS script only) |

On subsequent runs, the scripts automatically clean up previous instances and reuse existing security groups, ALBs, and certificates.

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| SFTP (root login) | `root` | `tester` |
| WordPress admin | `admin` | `password` |
| WordPress DB user | `wordpressuser` | `password` |
| Matomo DB user | `matomoadmin` | `password` (LAMP script only) |

> **Security Notice:** This script is intended for development, testing, and demo purposes only. It uses hardcoded default passwords and opens security group ports to `0.0.0.0/0`. Do not use it for production deployments without changing all credentials and restricting network access.

## Tech Stack

- **Shell:** Bash with strict mode (`set -euo pipefail`)
- **Cloud Platform:** AWS (EC2, VPC, Elastic IP, SSM, ALB, ACM, Route 53)
- **Web Server:** Apache HTTP Server
- **Database:** MariaDB
- **Language:** PHP
- **CMS:** WordPress
- **Analytics:** Matomo (LAMP script only)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
