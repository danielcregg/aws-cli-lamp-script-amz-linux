# AWS LAMP Stack Deployment Script for Amazon Linux

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat-square&logo=amazonwebservices&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

A single-command automation script that provisions AWS infrastructure and deploys a full LAMP stack (Linux, Apache, MariaDB, PHP) on an Amazon Linux 2023 EC2 instance, with optional extras including WordPress, VS Code Server, and Matomo Analytics.

## Overview

This project contains two Bash scripts that streamline the process of standing up a web server on AWS. The main deployment script handles everything from EC2 instance creation to software installation, while a helper script takes care of AWS CLI setup.

| Script | Purpose |
|--------|---------|
| `lamp-aws-installer-al.sh` | **Main script** -- creates AWS infrastructure (EC2, security group, key pair, Elastic IP) and deploys a LAMP stack with optional extras like WordPress and Matomo |
| `aws_cli_installer.sh` | **One-time setup helper** -- installs AWS CLI v2 on your local machine, sets the default region to `eu-west-1`, and prompts you to enter your AWS credentials |

## Features

- Fully automated EC2 instance provisioning with Amazon Linux 2023
- Cumulative installation flags for modular deployment (`-lamp`, `-sftp`, `-vscode`, `-db`, `-wp`, `-mt`)
- Automatic cleanup of previous instances on re-run
- Elastic IP reuse across deployments
- SSH key pair management with local `~/.ssh/config` setup
- WordPress installation with WP-CLI, Imagick, and database configuration
- Matomo Analytics integration with WordPress plugins
- Retry logic with exponential backoff for all AWS operations
- Color-coded terminal output with progress spinners

## Prerequisites

- **AWS CLI** installed and configured with valid credentials (run `aws_cli_installer.sh` or `aws configure`)
- **AWS IAM permissions** for EC2, VPC, Elastic IP, SSM parameter read, and key pair management
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
| Elastic IP | `elasticIPWebServerAuto` -- reused across runs |

On subsequent runs, the script automatically cleans up previous instances and reuses existing Elastic IPs and security groups.

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| SFTP (root login) | `root` | `tester` |
| WordPress admin | `admin` | `password` |
| WordPress DB user | `wordpressuser` | `password` |
| Matomo DB user | `matomoadmin` | `password` |

> **Security Notice:** This script is intended for development, testing, and demo purposes only. It uses hardcoded default passwords and opens security group ports to `0.0.0.0/0`. Do not use it for production deployments without changing all credentials and restricting network access.

## Tech Stack

- **Shell:** Bash with strict mode (`set -euo pipefail`)
- **Cloud Platform:** AWS (EC2, VPC, Elastic IP, SSM)
- **Web Server:** Apache HTTP Server
- **Database:** MariaDB
- **Language:** PHP
- **CMS:** WordPress (optional)
- **Analytics:** Matomo (optional)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
