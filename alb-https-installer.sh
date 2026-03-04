#!/bin/bash
set -euo pipefail

# Prevent Git Bash (MSYS2) on Windows from mangling forward-slash arguments
export MSYS_NO_PATHCONV=1

###########################################
# ALB + HTTPS Deployment Script
#
# Adds an Application Load Balancer with
# an ACM TLS certificate to an existing
# LAMP/WordPress EC2 deployment.
#
# Run AFTER lamp-aws-installer-al.sh
###########################################

###########################################
# Configuration Variables
###########################################
INSTANCE_TAG_NAME="WebServerAuto"
SSH_KEY_NAME="keyWebServerAuto"
ALB_SG_NAME="sgAlbWebServerAuto"
TG_NAME="tgWebServerAuto"
ALB_NAME="albWebServerAuto"
ACM_TIMEOUT=600                # Maximum wait time for certificate validation (seconds)
ALB_TIMEOUT=600                # Maximum wait time for ALB activation (seconds)
MAX_RETRIES=5                  # Maximum retry attempts for operations

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

# Print a numbered section header:  [1] Discovering resources
step() {
    STEP_NUM=$((STEP_NUM + 1))
    printf "\n${BOLD}${BLUE}[%d]${CLR} ${BOLD}%s${CLR}\n" "$STEP_NUM" "$1"
}

# Print an info sub-line:  ➜ Found instance i-abc123
info() { printf "  ${ARROW} %s\n" "$1"; }

# Print a success sub-line:  ✔ Hosted zone created
ok() { printf "  ${CHECK} %s\n" "$1"; }

# Print a warning:  · Certificate already exists
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

# OSC 8 clickable hyperlink: \e]8;;URL\e\\TEXT\e]8;;\e\\
link() { printf "\033]8;;%s\033\\%s\033]8;;\033\\" "$1" "$1"; }

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
printf "\n${BOLD}${CYAN}  ALB + HTTPS Deployment${CLR}\n"
printf "${DIM}  ──────────────────────${CLR}\n"

# ─────────────────────────────────────────
# Step 1: Discover existing resources
# ─────────────────────────────────────────
step "Discovering existing resources"

# Find EC2 instance
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null) || true
[ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "None" ] && \
    die "No running instance tagged '${INSTANCE_TAG_NAME}' found — run lamp-aws-installer-al.sh first"
ok "Instance: ${INSTANCE_ID}"

# Find VPC
VPC_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].VpcId' --output text)
[ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ] && die "Could not determine VPC for instance"
ok "VPC: ${VPC_ID}"

# Find all subnets in VPC (one per AZ for ALB)
SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].[AvailabilityZone,SubnetId]' --output text | \
    awk '!seen[$1]++ {print $2}')
[ -z "$SUBNET_IDS" ] && die "No subnets found in VPC ${VPC_ID}"

# Validate at least 2 AZs (ALB requirement)
AZ_COUNT=$(echo "$SUBNET_IDS" | wc -l)
[ "$AZ_COUNT" -lt 2 ] && die "ALB requires subnets in at least 2 availability zones (found ${AZ_COUNT})"
ok "Subnets span ${AZ_COUNT} availability zones"

# Find instance public IP (for SSH access later)
INSTANCE_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
if [ -n "$INSTANCE_PUBLIC_IP" ] && [ "$INSTANCE_PUBLIC_IP" != "None" ]; then
    ok "Public IP: ${INSTANCE_PUBLIC_IP}"
else
    note "No public IP found — WordPress URL update will require manual SSH"
    INSTANCE_PUBLIC_IP=""
fi

# ─────────────────────────────────────────
# Step 2: Domain name
# ─────────────────────────────────────────
step "Domain name"

while true; do
    printf "  ${ARROW} Enter your domain name (e.g. example.com): "
    read -r DOMAIN_NAME
    # Normalize to lowercase to avoid case-sensitive mismatches in Route 53/ACM lookups
    DOMAIN_NAME="${DOMAIN_NAME,,}"
    # Basic validation: must have at least one dot and no spaces
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

# Find only public hosted zones for this domain (filter out private zones)
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
        --caller-reference "alb-https-$(date +%s)" \
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

# Check for existing issued certificate (take first if multiple exist)
CERT_ARN=$(aws acm list-certificates --certificate-statuses ISSUED \
    --query "CertificateSummaryList[?DomainName=='${DOMAIN_NAME}'].CertificateArn | [0]" \
    --output text 2>/dev/null) || true

if [ -n "$CERT_ARN" ] && [ "$CERT_ARN" != "None" ]; then
    ok "Reusing existing certificate: ${CERT_ARN}"
else
    # Check for pending certificate (take first if multiple exist)
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

    # Wait for DNS validation details to become available (retry up to 60s)
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
    ok "Validation CNAME record created"

    # Wait for certificate to be issued
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

# ─────────────────────────────────────────
# Step 5: ALB security group
# ─────────────────────────────────────────
step "ALB security group"

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

# Ensure ports 80 and 443 are open (idempotent — skips duplicates, fails on real errors)
open_sg_port "$ALB_SG_ID" 80
open_sg_port "$ALB_SG_ID" 443
ok "Ports open: 80 (HTTP), 443 (HTTPS)"

# ─────────────────────────────────────────
# Step 6: Target group
# ─────────────────────────────────────────
step "Target group"

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

# Register instance (idempotent — re-registering an already registered target is a no-op)
aws elbv2 register-targets --target-group-arn "$TG_ARN" \
    --targets "Id=${INSTANCE_ID}" > /dev/null
ok "Instance registered in target group"

# ─────────────────────────────────────────
# Step 7: Application Load Balancer
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

# ─────────────────────────────────────────
# Step 8: Listeners
# ─────────────────────────────────────────
step "Configuring listeners"

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
# Step 9: Route 53 A record
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
aws route53 wait resource-record-sets-changed --id "$CHANGE_ID" 2>/dev/null || true
stop_spinner
ok "DNS change propagated"

# ─────────────────────────────────────────
# Step 10: Test HTTPS and update WordPress
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

    # Update WordPress URLs if WP is installed and SSH is available
    if [ -n "$INSTANCE_PUBLIC_IP" ] && [ -f "$KEY_PATH" ]; then
        info "Checking for WordPress installation…"
        WP_CHECK=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
            -i "$KEY_PATH" ec2-user@"$INSTANCE_PUBLIC_IP" \
            "sudo -u apache wp core is-installed --path=/var/www/html/ 2>/dev/null && echo 'installed'" 2>/dev/null) || true

        if [ "$WP_CHECK" = "installed" ]; then
            ssh -o StrictHostKeyChecking=accept-new -i "$KEY_PATH" ec2-user@"$INSTANCE_PUBLIC_IP" \
                "sudo -u apache wp option update siteurl 'https://${DOMAIN_NAME}' --path=/var/www/html/ --quiet 2>/dev/null && \
                 sudo -u apache wp option update home 'https://${DOMAIN_NAME}' --path=/var/www/html/ --quiet 2>/dev/null"
            ok "WordPress URLs updated to https://${DOMAIN_NAME}"
        else
            note "WordPress not detected — skipping URL update"
        fi
    else
        note "SSH key not available — skipping WordPress URL update"
    fi
else
    note "HTTPS test failed after ${MAX_RETRIES} attempts"
    note "DNS may still be propagating — WordPress URLs were NOT updated"
    note "Once HTTPS is working, update WordPress manually:"
    printf "      wp option update siteurl 'https://%s' --path=/var/www/html/\n" "$DOMAIN_NAME"
    printf "      wp option update home 'https://%s' --path=/var/www/html/\n" "$DOMAIN_NAME"
fi

# ─────────────────────────────────────────
# Step 11: Summary
# ─────────────────────────────────────────
step "Deployment complete"

ok "HTTPS URL: $(link "https://${DOMAIN_NAME}")"
ok "ALB DNS:   ${ALB_DNS}"
info "Instance:  ${INSTANCE_ID}"
info "VPC:       ${VPC_ID}"
info "Cert:      ${CERT_ARN}"
if [ "$HTTPS_OK" = true ]; then
    ok "WordPress is configured for HTTPS"
else
    note "Run the script again once DNS has propagated to update WordPress"
fi
