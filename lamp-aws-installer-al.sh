#!/bin/bash
set -euo pipefail

###########################################
# AWS LAMP Stack Deployment Script
#
# Automates the deployment of a LAMP stack
# on an AWS EC2 instance (Amazon Linux 2023).
#
# Optional components (cumulative flags):
#   -lamp   : Apache, MariaDB, PHP
#   -sftp   : + SFTP root access
#   -vscode : + VS Code Server
#   -db     : + Database management tools
#   -wp     : + WordPress (WP-CLI, Imagick)
#   -mt     : + Matomo Analytics
###########################################

###########################################
# Configuration Variables
###########################################
TIMEOUT=120                    # Maximum wait time for instance startup (seconds)
MAX_RETRIES=5                  # Maximum retry attempts for operations
INSTANCE_TYPE="t2.medium"      # AWS instance type

SSH_KEY_NAME="keyWebServerAuto"  
SECURITY_GROUP_NAME="sgWebServerAuto"
INSTANCE_TAG_NAME="WebServerAuto"
ELASTIC_IP_TAG_NAME="elasticIPWebServerAuto"

# Feature flags
INSTALL_LAMP=false
INSTALL_SFTP=false
INSTALL_VSCODE=false
INSTALL_DB=false
INSTALL_WORDPRESS=false
INSTALL_MATOMO=false

###########################################
# Helper Functions
###########################################

# --- Formatted output helpers ---
# Colours & symbols used throughout the script for uniform output.
readonly  CLR="\033[0m"
readonly  BOLD="\033[1m"
readonly  DIM="\033[2m"
readonly  GREEN="\033[32m"
readonly  YELLOW="\033[33m"
readonly  BLUE="\033[34m"
readonly  RED="\033[31m"
readonly  CYAN="\033[36m"
readonly  CHECK="${GREEN}✔${CLR}"
readonly  CROSS="${RED}✘${CLR}"
readonly  ARROW="${CYAN}➜${CLR}"
readonly  DOT="${DIM}·${CLR}"

# Current step counter (auto-incremented by step())
STEP_NUM=0

# Print a numbered section header:  [1] Cleaning up instances
step() {
    STEP_NUM=$((STEP_NUM + 1))
    printf "\n${BOLD}${BLUE}[%d]${CLR} ${BOLD}%s${CLR}\n" "$STEP_NUM" "$1"
}

# Print an info sub-line:  ➜ Reusing key pair
info() { printf "  ${ARROW} %s\n" "$1"; }

# Print a success sub-line:  ✔ Security group created
ok() { printf "  ${CHECK} %s\n" "$1"; }

# Print a warning:  · No existing instances found
note() { printf "  ${DOT} %s\n" "$1"; }

# Print an error and exit
die() { printf "\n  ${CROSS} ${RED}%s${CLR}\n" "$1"; exit 1; }

# Display a spinner on a single line while waiting.
# Usage:  spinner "Waiting for instance" &  SPIN_PID=$!
#         ... do work ...
#         stop_spinner
SPIN_PID=""
spinner() {
    local msg="$1"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    tput civis 2>/dev/null  # hide cursor
    while true; do
        printf "\r  ${YELLOW}%s${CLR} %s " "${frames[$i]}" "$msg"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.12
    done
}

stop_spinner() {
    if [ -n "$SPIN_PID" ] && kill -0 "$SPIN_PID" 2>/dev/null; then
        kill "$SPIN_PID" 2>/dev/null
        wait "$SPIN_PID" 2>/dev/null || true
        SPIN_PID=""
        printf "\r\033[K"  # clear spinner line
        tput cnorm 2>/dev/null  # restore cursor
    fi
}

# Ensure cursor is restored on exit
trap 'stop_spinner; tput cnorm 2>/dev/null' EXIT

# Retry a command with exponential backoff (base 5s × 2^attempt)
# Usage: retry_command "aws ec2 ..." "create instance" 3
retry_command() {
    local cmd="$1"
    local description="$2"
    local max_attempts="${3:-$MAX_RETRIES}"
    local attempt=1
    local output=""

    while [ "$attempt" -le "$max_attempts" ]; do
        if output=$(eval "$cmd" 2>&1); then
            echo "$output"
            return 0
        fi
        local wait_time=$((2 ** (attempt - 1) * 5))
        note "Attempt $attempt/$max_attempts failed — retrying in ${wait_time}s…"
        sleep "$wait_time"
        attempt=$((attempt + 1))
    done

    die "Failed to $description after $max_attempts attempts"
}

###########################################
# Command Line Argument Processing
###########################################
for arg in "$@"; do
    case $arg in
        -lamp)
            INSTALL_LAMP=true
            shift
            ;;
        -sftp)
            INSTALL_LAMP=true
            INSTALL_SFTP=true
            shift
            ;;
        -vscode)
            INSTALL_LAMP=true
            INSTALL_SFTP=true
            INSTALL_VSCODE=true
            shift
            ;;
        -db)
            INSTALL_LAMP=true
            INSTALL_SFTP=true
            INSTALL_VSCODE=true
            INSTALL_DB=true
            shift
            ;;
        -wp)
            INSTALL_LAMP=true
            INSTALL_SFTP=true
            INSTALL_VSCODE=true
            INSTALL_DB=true
            INSTALL_WORDPRESS=true
            shift
            ;;
        -mt)
            INSTALL_LAMP=true
            INSTALL_SFTP=true
            INSTALL_VSCODE=true
            INSTALL_DB=true
            INSTALL_WORDPRESS=true
            INSTALL_MATOMO=true
            shift
            ;;
    esac
done

###########################################
# Cleanup Phase
###########################################
printf "\n${BOLD}${CYAN}  AWS LAMP Stack Deployment${CLR}\n"
printf "${DIM}  ─────────────────────────${CLR}\n"

step "Checking for existing Elastic IPs"
EXISTING_ELASTIC_IP_ALLOCATION_IDS=$(aws ec2 describe-tags \
    --filters "Name=key,Values=Name" "Name=value,Values=${ELASTIC_IP_TAG_NAME}" "Name=resource-type,Values=elastic-ip" \
    --query 'Tags[*].ResourceId' --output text) || true
if [ -n "$EXISTING_ELASTIC_IP_ALLOCATION_IDS" ]; then
    for ALLOCATION_ID in $EXISTING_ELASTIC_IP_ALLOCATION_IDS; do
        ASSOC_ID=$(aws ec2 describe-addresses --allocation-ids "$ALLOCATION_ID" \
            --query 'Addresses[0].AssociationId' --output text) || true
        if [ -z "$ASSOC_ID" ] || [ "$ASSOC_ID" = "None" ]; then
            REUSE_ALLOCATION_ID=$ALLOCATION_ID
            break
        else
            aws ec2 disassociate-address --association-id "$ASSOC_ID" > /dev/null 2>&1 || true
            REUSE_ALLOCATION_ID=$ALLOCATION_ID
            break
        fi
    done
    ok "Found existing Elastic IP — will reuse"
else
    note "No existing Elastic IP found — will create one"
fi

step "Cleaning up old EC2 instances"
EXISTING_INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text) || true
if [ -n "$EXISTING_INSTANCE_IDS" ]; then
    for INSTANCE_ID in $EXISTING_INSTANCE_IDS; do
        aws ec2 create-tags --resources "$INSTANCE_ID" --tags "Key=Name,Value=${INSTANCE_TAG_NAME}-deleting" > /dev/null
    done
    aws ec2 terminate-instances --instance-ids $EXISTING_INSTANCE_IDS > /dev/null
    ok "Terminated previous instance(s)"
else
    note "No existing instances to clean up"
fi

step "Checking security group"
EXISTING_SG_ID=$(aws ec2 describe-security-groups --group-names "${SECURITY_GROUP_NAME}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null) || true
if [ -n "$EXISTING_SG_ID" ] && [ "$EXISTING_SG_ID" != "None" ]; then
    SG_ID="$EXISTING_SG_ID"
    ok "Reusing existing security group"
else
    note "No existing security group — will create one"
fi

step "Preparing SSH key pair"
# Create .ssh directory with proper permissions if it doesn't exist
if [ ! -d ~/.ssh ]; then
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
fi

# Clean stale entries from previous runs
rm -f ~/.ssh/known_hosts ~/.ssh/config

# Check for existing key pair with the same name
KEY_EXISTS=$(aws ec2 describe-key-pairs --key-names "${SSH_KEY_NAME}" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null) || true
if [ "$KEY_EXISTS" = "${SSH_KEY_NAME}" ]; then
    if [ -f ~/.ssh/${SSH_KEY_NAME} ]; then
        ok "Reusing existing key pair"
        REUSE_KEY=true
    else
        info "Local key file missing — recreating key pair"
        aws ec2 delete-key-pair --key-name ${SSH_KEY_NAME}
        REUSE_KEY=false
    fi
else
    note "No existing key pair — will create one"
    REUSE_KEY=false
fi

###########################################
# Resource Creation Phase
###########################################

# 1. Create and configure SSH key pair
step "Setting up SSH key pair"
if [ "$REUSE_KEY" = true ]; then
    chmod 600 ~/.ssh/${SSH_KEY_NAME}
    ok "Key pair ready"
else
    KEY_FILE=$(mktemp)
    if aws ec2 create-key-pair --key-name ${SSH_KEY_NAME} --query 'KeyMaterial' --output text > $KEY_FILE 2>/dev/null; then
        mv $KEY_FILE ~/.ssh/${SSH_KEY_NAME}
        chmod 600 ~/.ssh/${SSH_KEY_NAME}
        ok "New key pair created and saved"
    else
        rm -f $KEY_FILE
        die "Failed to create key pair"
    fi
fi

# 2. Create or reuse security group (ports are verified/added below regardless)
step "Configuring security group"
if [ -n "${SG_ID:-}" ]; then
    ok "Reusing existing security group"
else
    SG_ID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} \
        --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)

    if [ -z "$SG_ID" ]; then
        for i in $(seq 1 $MAX_RETRIES); do
            wait_time=$((2 ** i))
            note "Retrying in ${wait_time}s… (attempt $i/$MAX_RETRIES)"
            sleep $wait_time
            SG_ID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} \
                --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)
            [ -n "$SG_ID" ] && break
            [ $i -eq $MAX_RETRIES ] && die "Failed to create security group after $MAX_RETRIES attempts"
        done
    fi

    aws ec2 create-tags --resources "$SG_ID" --tags "Key=Name,Value=${SECURITY_GROUP_NAME}" > /dev/null
    ok "Security group created"
fi

# Ensure all required ports are open (idempotent — skips ports already open)
open_port_if_needed() {
    local port="$1"
    local label="$2"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port "$port" --cidr 0.0.0.0/0 > /dev/null 2>&1 || true
}
open_port_if_needed 22   "SSH"
open_port_if_needed 80   "HTTP"
open_port_if_needed 443  "HTTPS"
open_port_if_needed 8080 "Code Server"
ok "Ports open: 22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (Code Server)"

# 3. Launch EC2 instance using standard Amazon Linux 2023 AMI
#    The instance takes time to boot, so we launch it now and do other
#    setup work (Elastic IP, SSH config) while it starts up.
step "Launching EC2 instance"
info "Resolving latest Amazon Linux 2023 AMI…"
AMI_ID=$(aws ssm get-parameter --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" --query "Parameter.Value" --output text)

INSTANCE_ID=$(aws ec2 run-instances --image-id "$AMI_ID" --count 1 --instance-type "$INSTANCE_TYPE" \
    --key-name ${SSH_KEY_NAME} --security-group-ids "$SG_ID" \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":10,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${INSTANCE_TAG_NAME}}]" \
                        "ResourceType=volume,Tags=[{Key=Name,Value=volWebServerAuto}]" \
    --query 'Instances[0].InstanceId' --output text)
[ -z "$INSTANCE_ID" ] && die "Failed to launch instance"
ok "Instance launched (${INSTANCE_TYPE}) — booting in background"
LAUNCH_TIME=$(date +%s)

# 4. While the instance boots, prepare the Elastic IP and SSH config
step "Preparing Elastic IP"
if [ -n "${REUSE_ALLOCATION_ID:-}" ]; then
    ALLOCATION_ID=$REUSE_ALLOCATION_ID
    info "Reusing existing Elastic IP"
else
    ALLOCATION_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
    aws ec2 create-tags --resources "$ALLOCATION_ID" --tags Key=Name,Value=${ELASTIC_IP_TAG_NAME}
    info "Allocated new Elastic IP"
fi
ELASTIC_IP=$(aws ec2 describe-addresses --allocation-ids "$ALLOCATION_ID" --query 'Addresses[0].PublicIp' --output text)
ok "Elastic IP ready: ${ELASTIC_IP}"

# 5. Configure local SSH client (can be done before instance is running)
step "Configuring local SSH"
echo "Host vm
    HostName $ELASTIC_IP
    User ec2-user
    IdentityFile ~/.ssh/${SSH_KEY_NAME}" > ~/.ssh/config
chmod 600 ~/.ssh/config

[ ! -f ~/.ssh/${SSH_KEY_NAME} ] && die "SSH key file not found at ~/.ssh/${SSH_KEY_NAME}"
ok "SSH config written — you can connect with: ssh vm"

# 6. Now wait for the instance to finish booting
step "Waiting for instance to be ready"
spinner "Instance is booting…" &
SPIN_PID=$!
while true; do
    elapsed=$(( $(date +%s) - LAUNCH_TIME ))
    [ $elapsed -gt $TIMEOUT ] && { stop_spinner; die "Timed out after ${TIMEOUT}s waiting for instance"; }
    STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name' --output text)
    if [ "$STATE" = "running" ]; then
        stop_spinner
        ok "Instance is running (took ~${elapsed}s)"
        sleep 10
        break
    elif [ "$STATE" = "terminated" ] || [ "$STATE" = "shutting-down" ]; then
        stop_spinner
        die "Instance terminated unexpectedly"
    fi
    sleep 2
done

# 7. Associate Elastic IP now that instance is running
info "Attaching Elastic IP to instance…"
aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOCATION_ID" > /dev/null
ok "Elastic IP ${ELASTIC_IP} attached to instance"

# 8. Wait for SSH to become available on the new instance.
# StrictHostKeyChecking=no is used because this is a freshly created instance
# with no prior host key — the Elastic IP may have been reused from a previous run.
spinner "Waiting for SSH to become available…" &
SPIN_PID=$!
count=0
while ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@"$ELASTIC_IP" 'exit' 2>/dev/null; do
    count=$((count+1))
    if [ "$count" -ge "$MAX_RETRIES" ]; then
        stop_spinner
        die "Could not connect via SSH after $MAX_RETRIES attempts"
    fi
    sleep 2
done
stop_spinner
ok "SSH connection verified"

###########################################
# Installation Phase (skipped when no flags)
###########################################
if [ "$INSTALL_LAMP" = true ]; then
step "Installing software on remote instance"
ssh -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@$ELASTIC_IP 'set -e

# ── Remote output helpers (match the local look & feel) ──
CLR="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; RED="\033[31m"; CYAN="\033[36m"
CHECK="${GREEN}✔${CLR}"; CROSS="${RED}✘${CLR}"; ARROW="${CYAN}➜${CLR}"; DOT="${DIM}·${CLR}"
RSTEP=0
rstep() { RSTEP=$((RSTEP + 1)); printf "\n  ${BOLD}${BLUE}(%d)${CLR} ${BOLD}%s${CLR}\n" "$RSTEP" "$1"; }
rok()   { printf "      ${CHECK} %s\n" "$1"; }
rinfo() { printf "      ${ARROW} %s\n" "$1"; }
rnote() { printf "      ${DOT} %s\n" "$1"; }

#----------------
# LAMP Stack
#----------------
if [ '"$INSTALL_LAMP"' = true ]; then
    rstep "LAMP Stack"
    rinfo "Updating package repositories"
    sudo dnf clean all --quiet > /dev/null 2>&1
    sudo dnf makecache --quiet > /dev/null 2>&1
    rok "Package cache refreshed"

    rinfo "Installing Apache"
    sudo dnf install -y httpd > /dev/null 2>&1
    rok "Apache installed"

    rinfo "Installing MariaDB"
    MARIADB_LATEST_PACKAGE=$(dnf list available 2>/dev/null | grep -E "^mariadb[0-9]+-server" | awk "{print \$1}" | sort -V | tail -n 1)
    sudo dnf install -y "$MARIADB_LATEST_PACKAGE" > /dev/null 2>&1
    rok "MariaDB installed"

    rinfo "Installing PHP"
    sudo dnf install -y php > /dev/null 2>&1
    rok "PHP installed"

    rinfo "Configuring web server"
    sudo sed -i.bak -e "s/DirectoryIndex index.html/DirectoryIndex index.php index.html/" /etc/httpd/conf/httpd.conf || true
    sudo dnf install -y wget > /dev/null 2>&1
    sudo wget -q https://raw.githubusercontent.com/danielcregg/simple-php-website/main/index.php -P /var/www/html/
    sudo rm -f /var/www/html/index.html
    sudo chown -R apache:apache /var/www
    sudo systemctl enable --now httpd > /dev/null 2>&1
    sudo systemctl enable --now mariadb > /dev/null 2>&1
    rok "Apache & MariaDB running"
fi

#----------------
# SFTP Access
#----------------
if [ '"$INSTALL_SFTP"' = true ]; then
    rstep "SFTP Access"
    rinfo "Enabling root SSH login"
    sudo sed -i "/PermitRootLogin/c\PermitRootLogin yes" /etc/ssh/sshd_config
    echo "root:tester" | sudo chpasswd 2>/dev/null
    sudo systemctl restart sshd > /dev/null 2>&1
    rok "Root SFTP access enabled"
fi

#----------------
# VS Code Server
#----------------
if [ '"$INSTALL_VSCODE"' = true ]; then
    rstep "VS Code Server"
    rnote "Not yet implemented — skipping"
fi

#----------------
# WordPress
#----------------
if [ '"$INSTALL_WORDPRESS"' = true ]; then
    rstep "WordPress"
    rinfo "Installing WP-CLI"
    curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    sudo mv wp-cli.phar /usr/local/bin/wp
    rok "WP-CLI installed"

    rinfo "Downloading WordPress core"
    sudo mkdir -p /usr/share/httpd/.wp-cli/cache
    sudo chown -R apache:apache /usr/share/httpd/.wp-cli
    sudo -u apache wp core download --path=/var/www/html/ --quiet 2>/dev/null
    rok "WordPress downloaded"

    rinfo "Installing PHP extensions for WordPress"
    sudo dnf install -y php php-mysqlnd php-gd php-curl php-dom php-mbstring php-zip php-intl > /dev/null 2>&1
    rok "PHP extensions installed"

    rinfo "Compiling PHP Imagick from source"
    sudo dnf check-release-update > /dev/null 2>&1 || true
    sudo dnf upgrade --releasever=latest -y > /dev/null 2>&1
    sudo dnf install -y php-devel php-pear gcc ImageMagick ImageMagick-devel > /dev/null 2>&1
    pecl download Imagick > /dev/null 2>&1
    tar -xf imagick*.tgz
    IMAGICK_DIR=$(find . -type d -name "imagick*" | head -1)
    cd "$IMAGICK_DIR"
    phpize > /dev/null 2>&1
    ./configure > /dev/null 2>&1
    make > /dev/null 2>&1
    sudo make install > /dev/null 2>&1
    echo "extension=imagick.so" | sudo tee /etc/php.d/25-imagick.ini > /dev/null
    sudo systemctl restart php-fpm 2>/dev/null || true
    sudo systemctl restart httpd > /dev/null 2>&1
    cd ..
    rm -rf imagick*
    rok "Imagick compiled and loaded"

    rinfo "Creating WordPress database"
    sudo mysql -Bse "CREATE USER IF NOT EXISTS wordpressuser@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON *.* TO wordpressuser@localhost;FLUSH PRIVILEGES;" 2>/dev/null
    sudo -u apache wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/var/www/html/ --quiet 2>/dev/null
    sudo -u apache wp db create --path=/var/www/html/ --quiet 2>/dev/null
    sudo mysql -Bse "REVOKE ALL PRIVILEGES, GRANT OPTION FROM wordpressuser@localhost;GRANT ALL PRIVILEGES ON wordpress.* TO wordpressuser@localhost;FLUSH PRIVILEGES;" 2>/dev/null
    rok "Database created and secured"

    rinfo "Configuring WordPress"
    sudo mkdir -p /var/www/html/wp-content/uploads
    sudo chmod 775 /var/www/html/wp-content/uploads
    sudo chown apache:apache /var/www/html/wp-content/uploads
    sudo sed -i.bak -e "s/^upload_max_filesize.*/upload_max_filesize = 512M/g" /etc/php.ini
    sudo sed -i.bak -e "s/^post_max_size.*/post_max_size = 512M/g" /etc/php.ini
    sudo sed -i.bak -e "s/^max_execution_time.*/max_execution_time = 300/g" /etc/php.ini
    sudo sed -i.bak -e "s/^max_input_time.*/max_input_time = 300/g" /etc/php.ini
    sudo systemctl restart httpd > /dev/null 2>&1
    sudo -u apache wp core install --url=$(curl -s ifconfig.me) --title="Website Title" --admin_user="admin" --admin_password="password" --admin_email="x@y.com" --path=/var/www/html/ --quiet 2>/dev/null
    rok "WordPress configured"

    rinfo "Cleaning up default plugins and themes"
    sudo -u apache wp plugin list --status=inactive --field=name --path=/var/www/html/ 2>/dev/null | xargs --replace=% sudo -u apache wp plugin delete % --path=/var/www/html/ --quiet 2>/dev/null
    sudo -u apache wp theme list --status=inactive --field=name --path=/var/www/html/ 2>/dev/null | xargs --replace=% sudo -u apache wp theme delete % --path=/var/www/html/ --quiet 2>/dev/null
    rok "Inactive plugins and themes removed"

    rinfo "Installing All-in-One WP Migration plugin"
    sudo -u apache wp plugin install all-in-one-wp-migration --activate --path=/var/www/html/ --quiet 2>/dev/null
    rok "Plugin installed and activated"

    rinfo "Updating themes"
    sudo -u apache wp theme update --all --path=/var/www/html/ --quiet 2>/dev/null
    rok "Themes up to date"
fi

#----------------
# Matomo Analytics
#----------------
if [ '"$INSTALL_MATOMO"' = true ]; then
    rstep "Matomo Analytics"
    rinfo "Installing dependencies"
    sudo dnf install -y unzip php-dom php-xml php-mbstring > /dev/null 2>&1
    sudo systemctl restart httpd > /dev/null 2>&1
    rok "Dependencies installed"

    rinfo "Downloading and extracting Matomo"
    sudo wget -q https://builds.matomo.org/matomo.zip -P /var/www/html/
    sudo unzip -oq /var/www/html/matomo.zip -d /var/www/html/
    sudo chown -R apache:apache /var/www/html/matomo
    sudo rm -f /var/www/html/matomo.zip
    sudo rm -f /var/www/html/'\''How to install Matomo.html'\''
    rok "Matomo extracted"

    rinfo "Creating Matomo database"
    sudo mysql -Bse "CREATE DATABASE matomodb;CREATE USER matomoadmin@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON matomodb.* TO matomoadmin@localhost; FLUSH PRIVILEGES;" 2>/dev/null
    rok "Database ready"

    rinfo "Installing WordPress plugins for Matomo"
    sudo -u apache wp plugin install matomo --activate --path=/var/www/html/ --quiet 2>/dev/null
    sudo -u apache wp plugin install wp-piwik --activate --path=/var/www/html/ --quiet 2>/dev/null
    sudo -u apache wp plugin install super-progressive-web-apps --activate --path=/var/www/html/ --quiet 2>/dev/null
    rok "Matomo plugins activated"
fi
'

###########################################
# Final Status Summary
###########################################
step "Deployment complete"
PUBLIC_IP="$ELASTIC_IP"
ok "SSH access: ssh vm"
if [ "$INSTALL_LAMP" = true ]; then
    ok "Website: http://${PUBLIC_IP}"
fi
if [ "$INSTALL_SFTP" = true ]; then
    ok "SFTP: root@${PUBLIC_IP}  (password: tester)"
    info "WinSCP: https://dcus.short.gy/downloadWinSCP"
fi
if [ "$INSTALL_VSCODE" = true ]; then
    ok "VS Code: http://${PUBLIC_IP}:8080"
    info "Or SSH in and run: sudo code tunnel"
fi
if [ "$INSTALL_DB" = true ]; then
    ok "Adminer: http://${PUBLIC_IP}/adminer/?username=admin"
    ok "phpMyAdmin: http://${PUBLIC_IP}/phpmyadmin"
fi
if [ "$INSTALL_WORDPRESS" = true ]; then
    ok "WordPress: http://${PUBLIC_IP}"
    ok "WP Admin: http://${PUBLIC_IP}/wp-admin  (admin / password)"
fi
if [ "$INSTALL_MATOMO" = true ]; then
    ok "Matomo: http://${PUBLIC_IP}/matomo"
fi
else
    note "No installation flags provided — instance is ready but no software was installed"
fi
