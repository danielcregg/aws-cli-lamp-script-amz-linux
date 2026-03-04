#!/bin/bash
set -euo pipefail

# Prevent Git Bash (MSYS2) on Windows from mangling forward-slash arguments
export MSYS_NO_PATHCONV=1

###########################################
# AWS WordPress + HTTPS Deployment Script
#
# Deploys a LAMP stack with WordPress on
# an EC2 instance and configures HTTPS via
# an Application Load Balancer with an ACM
# TLS certificate and Route 53 DNS.
#
# No flags needed — installs everything.
###########################################

###########################################
# Configuration Variables
###########################################
TIMEOUT=120                    # Maximum wait time for instance startup (seconds)
MAX_RETRIES=5                  # Maximum retry attempts for operations
INSTANCE_TYPE="t2.medium"      # AWS instance type
ACM_TIMEOUT=600                # Maximum wait time for certificate validation (seconds)
ALB_TIMEOUT=600                # Maximum wait time for ALB activation (seconds)

SSH_KEY_NAME="keyWebServerAuto"
SECURITY_GROUP_NAME="sgWebServerAuto"
INSTANCE_TAG_NAME="WebServerAuto"
VOLUME_TAG_NAME="volWebServerAuto"
ALB_SG_NAME="sgAlbWebServerAuto"
TG_NAME="tgWebServerAuto"
ALB_NAME="albWebServerAuto"

###########################################
# Helper Functions
###########################################

# --- Formatted output helpers ---
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

# Print a numbered section header:  [1] Doing something
step() {
    STEP_NUM=$((STEP_NUM + 1))
    printf "\n${BOLD}${BLUE}[%d]${CLR} ${BOLD}%s${CLR}\n" "$STEP_NUM" "$1"
}

# Print an info sub-line:  ➜ Details here
info() { printf "  ${ARROW} %s\n" "$1"; }

# Print a success sub-line:  ✔ Done
ok() { printf "  ${CHECK} %s\n" "$1"; }

# Print a note:  · Something minor
note() { printf "  ${DOT} %s\n" "$1"; }

# Print an error and exit
die() { printf "\n  ${CROSS} ${RED}%s${CLR}\n" "$1"; exit 1; }

# Display a spinner while waiting
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

# OSC 8 clickable hyperlink
link() { printf "\033]8;;%s\033\\%s\033]8;;\033\\" "$1" "$1"; }

# Set private-key file permissions (works on both Windows/NTFS and Unix)
secure_key() {
    local kf="$1"
    chmod 600 "$kf" 2>/dev/null || true
    # On Windows, chmod alone is not enough — SSH checks NTFS ACLs
    if command -v icacls.exe > /dev/null 2>&1; then
        local win_path
        win_path=$(cygpath -w "$kf" 2>/dev/null || echo "$kf")
        icacls.exe "$win_path" /inheritance:r > /dev/null 2>&1 || true
        icacls.exe "$win_path" /grant:r "${USERNAME}:F" > /dev/null 2>&1 || true
    fi
}

# Open a port on a security group (idempotent — ignores duplicates, fails on real errors)
open_sg_port() {
    local sg_id="$1"
    local port="$2"
    local err
    err=$(aws ec2 authorize-security-group-ingress --group-id "$sg_id" \
        --protocol tcp --port "$port" --cidr 0.0.0.0/0 2>&1) && return 0
    echo "$err" | grep -q "InvalidPermission.Duplicate" && return 0
    die "Failed to open port $port: $err"
}

###########################################
# Main Script
###########################################
printf "\n${BOLD}${CYAN}  AWS WordPress + HTTPS Deployment${CLR}\n"
printf "${DIM}  ──────────────────────────────────${CLR}\n"

# ─────────────────────────────────────────
# Step 1: Clean up old EC2 instances
# ─────────────────────────────────────────
step "Cleaning up old EC2 instances"
EXISTING_INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text) || true
if [ -n "$EXISTING_INSTANCE_IDS" ]; then
    for INSTANCE_ID in $EXISTING_INSTANCE_IDS; do
        aws ec2 create-tags --resources "$INSTANCE_ID" --tags "Key=Name,Value=${INSTANCE_TAG_NAME}-deleting" > /dev/null
    done
    aws ec2 terminate-instances --instance-ids $EXISTING_INSTANCE_IDS > /dev/null
    spinner "Waiting for old instance(s) to terminate…" &
    SPIN_PID=$!
    aws ec2 wait instance-terminated --instance-ids $EXISTING_INSTANCE_IDS 2>/dev/null
    stop_spinner
    ok "Terminated previous instance(s)"
else
    note "No existing instances to clean up"
fi

# ─────────────────────────────────────────
# Step 2: Domain name
# ─────────────────────────────────────────
step "Domain name"

while true; do
    printf "  ${ARROW} Enter your domain name (e.g. example.com): "
    read -r DOMAIN_NAME
    # Normalize to lowercase
    DOMAIN_NAME="${DOMAIN_NAME,,}"
    if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        break
    fi
    note "Invalid domain name — please try again"
done
ok "Domain: ${DOMAIN_NAME}"

# ─────────────────────────────────────────
# Step 3: Route 53 hosted zone
# ─────────────────────────────────────────
step "Route 53 hosted zone"

# Find only public hosted zones for this domain
mapfile -t ZONE_IDS < <(
    aws route53 list-hosted-zones-by-name --dns-name "${DOMAIN_NAME}." \
        --query "HostedZones[?Name=='${DOMAIN_NAME}.' && Config.PrivateZone==\`false\`].Id" \
        --output text 2>/dev/null | tr '\t' '\n' | sed '/^$/d; /^None$/d'
)

if [ "${#ZONE_IDS[@]}" -gt 1 ]; then
    die "Multiple public hosted zones found for ${DOMAIN_NAME} — delete duplicates in the Route 53 console first"
elif [ "${#ZONE_IDS[@]}" -eq 1 ]; then
    HOSTED_ZONE_ID="${ZONE_IDS[0]##*/}"
    ok "Reusing existing hosted zone: ${HOSTED_ZONE_ID}"
else
    HOSTED_ZONE_ID=$(aws route53 create-hosted-zone --name "${DOMAIN_NAME}" \
        --caller-reference "wp-https-$(date +%s)" \
        --query 'HostedZone.Id' --output text)
    HOSTED_ZONE_ID="${HOSTED_ZONE_ID##*/}"
    ok "Hosted zone created: ${HOSTED_ZONE_ID}"
fi

# Display NS records
printf "\n"
info "Nameservers for ${DOMAIN_NAME}:"
aws route53 get-hosted-zone --id "$HOSTED_ZONE_ID" \
    --query 'DelegationSet.NameServers' --output text | tr '\t' '\n' | while read -r ns; do
    printf "      ${BOLD}%s${CLR}\n" "$ns"
done

printf "\n"
note "Update your domain registrar's nameservers to the values above."
note "DNS propagation can take up to 48 hours, but usually completes in minutes."
printf "\n  ${ARROW} Press ${BOLD}Enter${CLR} when your nameservers are configured… "
read -r

# ─────────────────────────────────────────
# Step 4: ACM certificate
# ─────────────────────────────────────────
step "Requesting ACM certificate"

# Check for existing issued certificate
CERT_ARN=$(aws acm list-certificates --certificate-statuses ISSUED \
    --query "CertificateSummaryList[?DomainName=='${DOMAIN_NAME}'].CertificateArn | [0]" \
    --output text 2>/dev/null) || true

CERT_ISSUED=false
if [ -n "$CERT_ARN" ] && [ "$CERT_ARN" != "None" ]; then
    ok "Reusing existing certificate: ${CERT_ARN}"
    CERT_ISSUED=true
else
    # Check for pending certificate
    CERT_ARN=$(aws acm list-certificates --certificate-statuses PENDING_VALIDATION \
        --query "CertificateSummaryList[?DomainName=='${DOMAIN_NAME}'].CertificateArn | [0]" \
        --output text 2>/dev/null) || true

    if [ -z "$CERT_ARN" ] || [ "$CERT_ARN" = "None" ]; then
        CERT_ARN=$(aws acm request-certificate --domain-name "${DOMAIN_NAME}" \
            --validation-method DNS --query 'CertificateArn' --output text)
        ok "Certificate requested: ${CERT_ARN}"
    else
        ok "Found pending certificate: ${CERT_ARN}"
    fi

    # Wait for DNS validation details (retry up to 60s)
    info "Waiting for validation details…"
    CNAME_NAME="None"
    CNAME_VALUE="None"
    for _ in $(seq 1 30); do
        CNAME_NAME=$(aws acm describe-certificate --certificate-arn "$CERT_ARN" \
            --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Name' --output text)
        CNAME_VALUE=$(aws acm describe-certificate --certificate-arn "$CERT_ARN" \
            --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Value' --output text)
        [ "$CNAME_NAME" != "None" ] && [ -n "$CNAME_NAME" ] && \
        [ "$CNAME_VALUE" != "None" ] && [ -n "$CNAME_VALUE" ] && break
        sleep 2
    done
    [ "$CNAME_NAME" = "None" ] || [ -z "$CNAME_NAME" ] && \
        die "ACM validation record not available — try again in a few minutes"

    info "Creating DNS validation record…"
    aws route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch '{
        "Changes": [{
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "'"$CNAME_NAME"'",
                "Type": "CNAME",
                "TTL": 300,
                "ResourceRecords": [{"Value": "'"$CNAME_VALUE"'"}]
            }
        }]
    }' > /dev/null
    ok "Validation CNAME created — certificate will validate while infrastructure is built"
fi

# ─────────────────────────────────────────
# Step 5: SSH key pair
# ─────────────────────────────────────────
step "Setting up SSH key pair"

# Create .ssh directory with proper permissions if it doesn't exist
if [ ! -d ~/.ssh ]; then
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
fi

# Clean stale entries from previous runs
rm -f ~/.ssh/known_hosts ~/.ssh/config

KEY_EXISTS=$(aws ec2 describe-key-pairs --key-names "${SSH_KEY_NAME}" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null) || true
if [ "$KEY_EXISTS" = "${SSH_KEY_NAME}" ]; then
    if [ -f ~/.ssh/${SSH_KEY_NAME} ]; then
        secure_key ~/.ssh/${SSH_KEY_NAME}
        ok "Reusing existing key pair"
    else
        info "Local key file missing — recreating key pair"
        aws ec2 delete-key-pair --key-name "${SSH_KEY_NAME}" > /dev/null
        KEY_FILE=$(mktemp)
        if aws ec2 create-key-pair --key-name "${SSH_KEY_NAME}" --query 'KeyMaterial' --output text > "$KEY_FILE" 2>/dev/null; then
            mv "$KEY_FILE" ~/.ssh/${SSH_KEY_NAME}
            secure_key ~/.ssh/${SSH_KEY_NAME}
            ok "New key pair created and saved"
        else
            rm -f "$KEY_FILE"
            die "Failed to create key pair"
        fi
    fi
else
    note "No existing key pair — creating one"
    KEY_FILE=$(mktemp)
    if aws ec2 create-key-pair --key-name "${SSH_KEY_NAME}" --query 'KeyMaterial' --output text > "$KEY_FILE" 2>/dev/null; then
        mv "$KEY_FILE" ~/.ssh/${SSH_KEY_NAME}
        secure_key ~/.ssh/${SSH_KEY_NAME}
        ok "New key pair created and saved"
    else
        rm -f "$KEY_FILE"
        die "Failed to create key pair"
    fi
fi

# ─────────────────────────────────────────
# Step 6: Security group
# ─────────────────────────────────────────
step "Configuring security group"

SG_ID=$(aws ec2 describe-security-groups --group-names "${SECURITY_GROUP_NAME}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null) || true

if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
    ok "Reusing existing security group"
else
    SG_ID=$(aws ec2 create-security-group --group-name "${SECURITY_GROUP_NAME}" \
        --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)

    if [ -z "$SG_ID" ]; then
        for i in $(seq 1 $MAX_RETRIES); do
            wait_time=$((2 ** i))
            note "Retrying in ${wait_time}s… (attempt $i/$MAX_RETRIES)"
            sleep $wait_time
            SG_ID=$(aws ec2 create-security-group --group-name "${SECURITY_GROUP_NAME}" \
                --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)
            [ -n "$SG_ID" ] && break
            [ $i -eq $MAX_RETRIES ] && die "Failed to create security group after $MAX_RETRIES attempts"
        done
    fi

    aws ec2 create-tags --resources "$SG_ID" --tags "Key=Name,Value=${SECURITY_GROUP_NAME}" > /dev/null
    ok "Security group created"
fi

# Ensure all required ports are open
open_sg_port "$SG_ID" 22
open_sg_port "$SG_ID" 80
open_sg_port "$SG_ID" 443
open_sg_port "$SG_ID" 8080
ok "Ports open: 22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (Code Server)"

# ─────────────────────────────────────────
# Step 7: Launch EC2 instance
# ─────────────────────────────────────────
step "Launching EC2 instance"
info "Resolving latest Amazon Linux 2023 AMI…"
AMI_ID=$(aws ssm get-parameter --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" --query "Parameter.Value" --output text)

INSTANCE_ID=$(aws ec2 run-instances --image-id "$AMI_ID" --count 1 --instance-type "$INSTANCE_TYPE" \
    --key-name "${SSH_KEY_NAME}" --security-group-ids "$SG_ID" \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":10,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${INSTANCE_TAG_NAME}}]" \
                        "ResourceType=volume,Tags=[{Key=Name,Value=${VOLUME_TAG_NAME}}]" \
    --query 'Instances[0].InstanceId' --output text)
[ -z "$INSTANCE_ID" ] && die "Failed to launch instance"
ok "Instance launched (${INSTANCE_TYPE}) — booting in background"
LAUNCH_TIME=$(date +%s)

# ─────────────────────────────────────────
# Step 8: Wait for instance to be ready
# ─────────────────────────────────────────
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

# Get the instance's auto-assigned public IP
INSTANCE_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
[ -z "$INSTANCE_PUBLIC_IP" ] || [ "$INSTANCE_PUBLIC_IP" = "None" ] && \
    die "Instance has no public IP — ensure the subnet assigns public IPs"
ok "Public IP: ${INSTANCE_PUBLIC_IP}"

# ─────────────────────────────────────────
# Step 9: Local SSH config
# ─────────────────────────────────────────
step "Configuring local SSH"
echo "Host vm
    HostName $INSTANCE_PUBLIC_IP
    User ec2-user
    IdentityFile ~/.ssh/${SSH_KEY_NAME}" > ~/.ssh/config
chmod 600 ~/.ssh/config

[ ! -f ~/.ssh/${SSH_KEY_NAME} ] && die "SSH key file not found at ~/.ssh/${SSH_KEY_NAME}"
ok "SSH config written — you can connect with: ssh vm"

# Wait for SSH to become available
spinner "Waiting for SSH to become available…" &
SPIN_PID=$!
count=0
while ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@"$INSTANCE_PUBLIC_IP" 'exit' 2>/dev/null; do
    count=$((count+1))
    if [ "$count" -ge "$MAX_RETRIES" ]; then
        stop_spinner
        die "Could not connect via SSH after $MAX_RETRIES attempts"
    fi
    sleep 2
done
stop_spinner
ok "SSH connection verified"

# Set a friendly hostname
ssh -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@"$INSTANCE_PUBLIC_IP" \
    "sudo hostnamectl set-hostname ${INSTANCE_TAG_NAME}" > /dev/null 2>&1
ok "Hostname set to ${INSTANCE_TAG_NAME}"

# ─────────────────────────────────────────
# Step 10: Install software on remote instance
# ─────────────────────────────────────────
step "Installing software on remote instance"
ssh -t -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@"$INSTANCE_PUBLIC_IP" 'set -eo pipefail

# ── Remote output helpers (match the local look & feel) ──
CLR="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; RED="\033[31m"; CYAN="\033[36m"
CHECK="${GREEN}✔${CLR}"; CROSS="${RED}✘${CLR}"; ARROW="${CYAN}➜${CLR}"; DOT="${DIM}·${CLR}"
RSTEP=0
rstep() { RSTEP=$((RSTEP + 1)); printf "\n  ${BOLD}${BLUE}(%d)${CLR} ${BOLD}%s${CLR}\n" "$RSTEP" "$1"; }
rok()   { printf "      ${CHECK} %s\n" "$1"; }
rinfo() { printf "      ${ARROW} %s\n" "$1"; }
rnote() { printf "      ${DOT} %s\n" "$1"; }

# Spinner for long-running remote commands
RSPIN_PID=""
rspin() {
    local msg="$1"
    local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
    local i=0
    tput civis 2>/dev/null || true
    while true; do
        printf "\r      ${YELLOW}%s${CLR} %s " "${frames[$i]}" "$msg"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.12
    done &
    RSPIN_PID=$!
}
rstop() {
    if [ -n "$RSPIN_PID" ] && kill -0 "$RSPIN_PID" 2>/dev/null; then
        kill "$RSPIN_PID" 2>/dev/null
        wait "$RSPIN_PID" 2>/dev/null || true
        RSPIN_PID=""
        printf "\r\033[K"
        tput cnorm 2>/dev/null || true
    fi
}
trap "rstop; tput cnorm 2>/dev/null || true" EXIT

#----------------
# LAMP Stack
#----------------
rstep "LAMP Stack"
rspin "Updating package repositories"
sudo dnf clean all --quiet > /dev/null 2>&1
sudo dnf makecache --quiet > /dev/null 2>&1
rstop; rok "Package cache refreshed"

rspin "Installing Apache"
sudo dnf install -y httpd > /dev/null 2>&1
rstop; rok "Apache installed"

rspin "Installing MariaDB"
MARIADB_LATEST_PACKAGE=$(dnf list available 2>/dev/null | grep -E "^mariadb[0-9]+-server" | awk "{print \$1}" | sort -V | tail -n 1)
sudo dnf install -y "$MARIADB_LATEST_PACKAGE" > /dev/null 2>&1
rstop; rok "MariaDB installed"

rspin "Installing PHP"
sudo dnf install -y php > /dev/null 2>&1
rstop; rok "PHP installed"

rspin "Configuring web server"
sudo sed -i.bak -e "s/DirectoryIndex index.html/DirectoryIndex index.php index.html/" /etc/httpd/conf/httpd.conf || true
sudo dnf install -y wget > /dev/null 2>&1
sudo wget -q https://raw.githubusercontent.com/danielcregg/simple-php-website/main/index.php -P /var/www/html/
sudo rm -f /var/www/html/index.html
sudo chown -R apache:apache /var/www
sudo systemctl enable --now httpd > /dev/null 2>&1
sudo systemctl enable --now mariadb > /dev/null 2>&1
rstop; rok "Apache & MariaDB running"

#----------------
# SFTP Access
#----------------
rstep "SFTP Access"
rspin "Enabling root SSH login"
sudo sed -i "/PermitRootLogin/c\PermitRootLogin yes" /etc/ssh/sshd_config
echo "root:tester" | sudo chpasswd 2>/dev/null
sudo systemctl restart sshd > /dev/null 2>&1
rstop; rok "Root SFTP access enabled"

#----------------
# WordPress
#----------------
rstep "WordPress"
rspin "Installing WP-CLI"
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp
rstop; rok "WP-CLI installed"

rspin "Downloading WordPress core"
sudo mkdir -p /usr/share/httpd/.wp-cli/cache
sudo chown -R apache:apache /usr/share/httpd/.wp-cli
sudo -u apache wp core download --path=/var/www/html/ --quiet 2>/dev/null
rstop; rok "WordPress downloaded"

rspin "Installing PHP extensions"
sudo dnf install -y php php-mysqlnd php-gd php-curl php-dom php-mbstring php-zip php-intl > /dev/null 2>&1
rstop; rok "PHP extensions installed"

rspin "Compiling PHP Imagick from source (this may take a minute)"
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
rstop; rok "Imagick compiled and loaded"

rspin "Creating WordPress database"
sudo mysql -Bse "CREATE USER IF NOT EXISTS wordpressuser@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON *.* TO wordpressuser@localhost;FLUSH PRIVILEGES;" 2>/dev/null
sudo -u apache wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/var/www/html/ --quiet 2>/dev/null
sudo -u apache wp db create --path=/var/www/html/ --quiet 2>/dev/null
sudo mysql -Bse "REVOKE ALL PRIVILEGES, GRANT OPTION FROM wordpressuser@localhost;GRANT ALL PRIVILEGES ON wordpress.* TO wordpressuser@localhost;FLUSH PRIVILEGES;" 2>/dev/null
rstop; rok "Database created and secured"

rspin "Configuring WordPress"
sudo mkdir -p /var/www/html/wp-content/uploads
sudo chmod 775 /var/www/html/wp-content/uploads
sudo chown apache:apache /var/www/html/wp-content/uploads
sudo sed -i.bak -e "s/^upload_max_filesize.*/upload_max_filesize = 512M/g" /etc/php.ini
sudo sed -i.bak -e "s/^post_max_size.*/post_max_size = 512M/g" /etc/php.ini
sudo sed -i.bak -e "s/^max_execution_time.*/max_execution_time = 300/g" /etc/php.ini
sudo sed -i.bak -e "s/^max_input_time.*/max_input_time = 300/g" /etc/php.ini
sudo systemctl restart httpd > /dev/null 2>&1
sudo -u apache wp core install --url=$(curl -s ifconfig.me) --title="Website Title" --admin_user="admin" --admin_password="password" --admin_email="x@y.com" --path=/var/www/html/ --quiet 2>/dev/null
rstop; rok "WordPress configured"

rspin "Cleaning up default plugins and themes"
sudo -u apache wp plugin list --status=inactive --field=name --path=/var/www/html/ 2>/dev/null | xargs --replace=% sudo -u apache wp plugin delete % --path=/var/www/html/ --quiet 2>/dev/null
sudo -u apache wp theme list --status=inactive --field=name --path=/var/www/html/ 2>/dev/null | xargs --replace=% sudo -u apache wp theme delete % --path=/var/www/html/ --quiet 2>/dev/null
rstop; rok "Inactive plugins and themes removed"

rspin "Installing All-in-One WP Migration plugin"
sudo -u apache wp plugin install all-in-one-wp-migration --activate --path=/var/www/html/ --quiet 2>/dev/null
rstop; rok "Plugin installed and activated"

rspin "Updating themes"
sudo -u apache wp theme update --all --path=/var/www/html/ --quiet 2>/dev/null
rstop; rok "Themes up to date"
'

# ─────────────────────────────────────────
# Step 11: ALB security group
# ─────────────────────────────────────────
step "ALB security group"

# Find VPC from the instance
VPC_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].VpcId' --output text)
[ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ] && die "Could not determine VPC for instance"

ALB_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${ALB_SG_NAME}" "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null) || true

if [ -n "$ALB_SG_ID" ] && [ "$ALB_SG_ID" != "None" ]; then
    ok "Reusing existing security group: ${ALB_SG_ID}"
else
    ALB_SG_ID=$(aws ec2 create-security-group --group-name "${ALB_SG_NAME}" \
        --description "ALB security group" --vpc-id "$VPC_ID" \
        --query 'GroupId' --output text)
    aws ec2 create-tags --resources "$ALB_SG_ID" --tags "Key=Name,Value=${ALB_SG_NAME}" > /dev/null
    ok "Security group created: ${ALB_SG_ID}"
fi

open_sg_port "$ALB_SG_ID" 80
open_sg_port "$ALB_SG_ID" 443
ok "Ports open: 80 (HTTP), 443 (HTTPS)"

# ─────────────────────────────────────────
# Step 12: Target group
# ─────────────────────────────────────────
step "Target group"

# Find subnets in VPC (one per AZ for ALB)
SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].[AvailabilityZone,SubnetId]' --output text | \
    awk '!seen[$1]++ {print $2}')
[ -z "$SUBNET_IDS" ] && die "No subnets found in VPC ${VPC_ID}"

# Validate at least 2 AZs (ALB requirement)
AZ_COUNT=$(echo "$SUBNET_IDS" | wc -l)
[ "$AZ_COUNT" -lt 2 ] && die "ALB requires subnets in at least 2 availability zones (found ${AZ_COUNT})"
info "Subnets span ${AZ_COUNT} availability zones"

TG_ARN=$(aws elbv2 describe-target-groups --names "${TG_NAME}" \
    --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null) || true

if [ -n "$TG_ARN" ] && [ "$TG_ARN" != "None" ]; then
    # Validate the existing target group is in the correct VPC
    TG_VPC=$(aws elbv2 describe-target-groups --target-group-arns "$TG_ARN" \
        --query 'TargetGroups[0].VpcId' --output text)
    [ "$TG_VPC" != "$VPC_ID" ] && die "Target group ${TG_NAME} is in VPC ${TG_VPC}, expected ${VPC_ID}"
    ok "Reusing existing target group"
else
    TG_ARN=$(aws elbv2 create-target-group --name "${TG_NAME}" \
        --protocol HTTP --port 80 --vpc-id "$VPC_ID" \
        --target-type instance \
        --health-check-path "/" --health-check-protocol HTTP \
        --query 'TargetGroups[0].TargetGroupArn' --output text)
    ok "Target group created"
fi

# Register instance (idempotent)
aws elbv2 register-targets --target-group-arn "$TG_ARN" \
    --targets "Id=${INSTANCE_ID}" > /dev/null
ok "Instance registered in target group"

# Wait for target to become healthy before proceeding
spinner "Waiting for target health check…" &
SPIN_PID=$!
aws elbv2 wait target-in-service --target-group-arn "$TG_ARN" \
    --targets "Id=${INSTANCE_ID}" 2>/dev/null || true
stop_spinner
ok "Target health check passed"

# ─────────────────────────────────────────
# Step 13: Application Load Balancer
# ─────────────────────────────────────────
step "Application Load Balancer"

ALB_ARN=$(aws elbv2 describe-load-balancers --names "${ALB_NAME}" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null) || true

if [ -n "$ALB_ARN" ] && [ "$ALB_ARN" != "None" ]; then
    ok "Reusing existing load balancer"
    ALB_DNS=$(aws elbv2 describe-load-balancers --names "${ALB_NAME}" \
        --query 'LoadBalancers[0].DNSName' --output text)
    ALB_ZONE_ID=$(aws elbv2 describe-load-balancers --names "${ALB_NAME}" \
        --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)
else
    ALB_ARN=$(aws elbv2 create-load-balancer --name "${ALB_NAME}" \
        --subnets $SUBNET_IDS \
        --security-groups "$ALB_SG_ID" \
        --scheme internet-facing --type application \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)
    ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
        --query 'LoadBalancers[0].DNSName' --output text)
    ALB_ZONE_ID=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
        --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)
    ok "Load balancer created"

    # Wait for ALB to become active
    spinner "Waiting for load balancer to become active…" &
    SPIN_PID=$!
    ALB_START=$(date +%s)
    while true; do
        elapsed=$(( $(date +%s) - ALB_START ))
        [ "$elapsed" -gt "$ALB_TIMEOUT" ] && { stop_spinner; die "ALB activation timed out after ${ALB_TIMEOUT}s"; }
        ALB_STATE=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
            --query 'LoadBalancers[0].State.Code' --output text)
        if [ "$ALB_STATE" = "active" ]; then
            stop_spinner
            ok "Load balancer active"
            break
        elif [ "$ALB_STATE" = "failed" ]; then
            stop_spinner
            die "Load balancer provisioning failed"
        fi
        sleep 5
    done
fi
info "DNS: ${ALB_DNS}"

# Tag the ALB's Elastic IPs with meaningful names
ALB_ENI_IDS=$(aws ec2 describe-network-interfaces \
    --filters "Name=description,Values=ELB app/${ALB_NAME}/*" \
    --query 'NetworkInterfaces[*].NetworkInterfaceId' --output text)
if [ -n "$ALB_ENI_IDS" ]; then
    for ENI_ID in $ALB_ENI_IDS; do
        AZ=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI_ID" \
            --query 'NetworkInterfaces[0].AvailabilityZone' --output text)
        AZ_SUFFIX="${AZ##*-}"  # e.g. "west-1a" → "1a"
        EIP_ALLOC=$(aws ec2 describe-addresses \
            --filters "Name=network-interface-id,Values=${ENI_ID}" \
            --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)
        if [ -n "$EIP_ALLOC" ] && [ "$EIP_ALLOC" != "None" ]; then
            aws ec2 create-tags --resources "$EIP_ALLOC" \
                --tags "Key=Name,Value=eipAlbWebServerAuto-${AZ_SUFFIX}" > /dev/null
        fi
    done
    ok "ALB Elastic IPs tagged"
fi

# ─────────────────────────────────────────
# Step 14: Configuring listeners
# ─────────────────────────────────────────
step "Configuring listeners"

# Ensure certificate is issued before creating HTTPS listener
if [ "$CERT_ISSUED" != true ]; then
    spinner "Waiting for certificate validation (up to 10 min)…" &
    SPIN_PID=$!
    START_TIME=$(date +%s)
    while true; do
        elapsed=$(( $(date +%s) - START_TIME ))
        [ $elapsed -gt $ACM_TIMEOUT ] && { stop_spinner; die "Certificate validation timed out after ${ACM_TIMEOUT}s"; }
        STATUS=$(aws acm describe-certificate --certificate-arn "$CERT_ARN" \
            --query 'Certificate.Status' --output text)
        if [ "$STATUS" = "ISSUED" ]; then
            stop_spinner
            ok "Certificate issued"
            break
        elif [ "$STATUS" = "FAILED" ]; then
            stop_spinner
            die "Certificate validation failed"
        fi
        sleep 10
    done
fi

# HTTPS listener (443 → target group)
HTTPS_LISTENER=$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
    --query "Listeners[?Port==\`443\`].ListenerArn" --output text 2>/dev/null) || true

if [ -n "$HTTPS_LISTENER" ] && [ "$HTTPS_LISTENER" != "None" ]; then
    ok "HTTPS listener already exists"
else
    aws elbv2 create-listener --load-balancer-arn "$ALB_ARN" \
        --protocol HTTPS --port 443 \
        --certificates "CertificateArn=${CERT_ARN}" \
        --default-actions "Type=forward,TargetGroupArn=${TG_ARN}" > /dev/null
    ok "HTTPS listener created (443 → target group)"
fi

# HTTP listener (80 → redirect to HTTPS)
HTTP_LISTENER=$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
    --query "Listeners[?Port==\`80\`].ListenerArn" --output text 2>/dev/null) || true

if [ -n "$HTTP_LISTENER" ] && [ "$HTTP_LISTENER" != "None" ]; then
    ok "HTTP listener already exists"
else
    aws elbv2 create-listener --load-balancer-arn "$ALB_ARN" \
        --protocol HTTP --port 80 \
        --default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' > /dev/null
    ok "HTTP listener created (80 → redirect to HTTPS)"
fi

# ─────────────────────────────────────────
# Step 15: Route 53 A record
# ─────────────────────────────────────────
step "Route 53 A record"

CHANGE_ID=$(aws route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch '{
    "Changes": [{
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": "'"${DOMAIN_NAME}"'",
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "'"${ALB_ZONE_ID}"'",
                "DNSName": "'"${ALB_DNS}"'",
                "EvaluateTargetHealth": false
            }
        }
    }]
}' --query 'ChangeInfo.Id' --output text)
ok "A record: ${DOMAIN_NAME} → ALB"

# Wait for DNS change to propagate within Route 53
spinner "Waiting for Route 53 DNS propagation…" &
SPIN_PID=$!
if aws route53 wait resource-record-sets-changed --id "$CHANGE_ID" 2>/dev/null; then
    stop_spinner
    ok "DNS change propagated"
else
    stop_spinner
    note "Route 53 wait timed out — DNS may still be propagating"
fi

# ─────────────────────────────────────────
# Step 16: Test HTTPS and update WordPress
# ─────────────────────────────────────────
step "Testing HTTPS connectivity"

HTTPS_OK=false
for attempt in $(seq 1 $MAX_RETRIES); do
    if curl -sSf --max-time 10 "https://${DOMAIN_NAME}" > /dev/null 2>&1; then
        HTTPS_OK=true
        break
    fi
    note "Attempt ${attempt}/${MAX_RETRIES} — waiting 15s for DNS propagation…"
    sleep 15
done

KEY_PATH="${HOME}/.ssh/${SSH_KEY_NAME}"

if [ "$HTTPS_OK" = true ]; then
    ok "HTTPS is working"

    # Update WordPress URLs to HTTPS
    if [ -f "$KEY_PATH" ]; then
        info "Updating WordPress URLs to HTTPS…"
        ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
            -i "$KEY_PATH" ec2-user@"$INSTANCE_PUBLIC_IP" \
            "sudo -u apache wp option update siteurl 'https://${DOMAIN_NAME}' --path=/var/www/html/ --quiet 2>/dev/null && \
             sudo -u apache wp option update home 'https://${DOMAIN_NAME}' --path=/var/www/html/ --quiet 2>/dev/null"
        ok "WordPress URLs updated to https://${DOMAIN_NAME}"
    fi
else
    note "HTTPS test failed after ${MAX_RETRIES} attempts"
    note "DNS may still be propagating — WordPress URLs were NOT updated"
    note "Once HTTPS is working, update WordPress manually:"
    printf "      wp option update siteurl 'https://%s' --path=/var/www/html/\n" "$DOMAIN_NAME"
    printf "      wp option update home 'https://%s' --path=/var/www/html/\n" "$DOMAIN_NAME"
fi

# ─────────────────────────────────────────
# Step 17: Deployment complete
# ─────────────────────────────────────────
step "Deployment complete"

ok "HTTPS URL:  $(link "https://${DOMAIN_NAME}")"
ok "WP Admin:   $(link "https://${DOMAIN_NAME}/wp-admin")  (admin / password)"
ok "SSH access: ssh vm"
ok "SFTP:       root@${INSTANCE_PUBLIC_IP}  (password: tester)  [Note: IP may change if instance is restarted]"
info "ALB DNS:   ${ALB_DNS}"
info "Instance:  ${INSTANCE_ID}"
info "Cert:      ${CERT_ARN}"
if [ "$HTTPS_OK" = true ]; then
    ok "WordPress is configured for HTTPS"
else
    note "Run the script again once DNS has propagated to update WordPress"
fi
