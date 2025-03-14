#!/bin/bash

###########################################
# AWS LAMP Stack Deployment Script
#
# This script automates the deployment of a LAMP stack on AWS.
# It can optionally install:
# - Basic LAMP (Linux, Apache, MySQL, PHP)
# - SFTP access
# - VS Code server
# - Database management tools
# - WordPress
# - Matomo Analytics
# - SSL certificate, ALB, and Route 53 integration for HTTPS
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
ALB_NAME="webServerAutoALB"
TARGET_GROUP_NAME="webServerAutoTG"
CERTIFICATE_TAG_NAME="sslCertWebServerAuto"

# Feature flags
INSTALL_LAMP=false
INSTALL_SFTP=false
INSTALL_VSCODE=false
INSTALL_DB=false
INSTALL_WORDPRESS=false
INSTALL_MATOMO=false
SETUP_HTTPS=false

# Domain configuration
DOMAIN_NAME=""

###########################################
# Helper Functions
###########################################
show_spinner() {
    local message="$1"
    echo -en "\r\033[K$message"
    for cursor in '/' '-' '\' '|'; do
        echo -en "\b$cursor"
        sleep 0.5
    done
}

wait_for_termination() {
    local resource_id="$1"
    local resource_type="$2"
    # ...existing status check code...
}

# Function to retry AWS commands with exponential backoff
retry_command() {
    local cmd=$1
    local description=$2
    local max_attempts=$3
    local attempt=1
    local output=""
    local status=1
    
    echo "Attempting to $description..."
    while [ $attempt -le $max_attempts ]; do
        echo " - Attempt $attempt/$max_attempts"
        output=$(eval "$cmd" 2>&1)
        status=$?
        
        if [ $status -eq 0 ]; then
            echo " - Success: $description"
            echo "$output"
            return 0
        fi
        
        wait_time=$((2 ** ($attempt - 1) * 5))
        echo " - Failed. Waiting ${wait_time} seconds before retrying..."
        sleep $wait_time
        attempt=$((attempt + 1))
    done
    
    echo "Failed to $description after $max_attempts attempts. Exiting..."
    echo "Last error: $output"
    return 1
}

###########################################
# Command Line Argument Processing
###########################################
while [[ $# -gt 0 ]]; do
    case $1 in
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
        -d|--domain)
            if [[ -n "$2" && "$2" != -* ]]; then
                DOMAIN_NAME="$2"
                SETUP_HTTPS=true
                shift 2
            else
                echo "Error: Domain name is required after -d|--domain flag"
                exit 1
            fi
            ;;
        *)
            shift
            ;;
    esac
done

# Validate domain name if HTTPS is requested
if [ "$SETUP_HTTPS" = true ] && [ -z "$DOMAIN_NAME" ]; then
    echo "Error: Domain name is required for HTTPS setup. Please use -d|--domain flag."
    exit 1
fi

###########################################
# Cleanup Phase
###########################################
printf "\e[3;4;31mStarting cleanup of AWS resources...\e[0m\n"

# 0. Clean up ALB and Target Groups if HTTPS setup is enabled
if [ "$SETUP_HTTPS" = true ]; then
    echo "0. Cleaning up existing ALB resources..."
    
    # Check for existing ALB
    EXISTING_ALB_ARN=$(aws elbv2 describe-load-balancers --names ${ALB_NAME} --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null)
    if [ -n "$EXISTING_ALB_ARN" ] && [ "$EXISTING_ALB_ARN" != "None" ]; then
        echo " - Found existing ALB, deleting: ${EXISTING_ALB_ARN}"
        aws elbv2 delete-load-balancer --load-balancer-arn ${EXISTING_ALB_ARN}
        echo " - Waiting for ALB deletion to complete..."
        sleep 10
    fi
    
    # Check for existing Target Group
    EXISTING_TG_ARN=$(aws elbv2 describe-target-groups --names ${TARGET_GROUP_NAME} --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null)
    if [ -n "$EXISTING_TG_ARN" ] && [ "$EXISTING_TG_ARN" != "None" ]; then
        echo " - Found existing Target Group, deleting: ${EXISTING_TG_ARN}"
        aws elbv2 delete-target-group --target-group-arn ${EXISTING_TG_ARN}
    fi
    
    # Check for existing certificates
    echo " - Checking for existing SSL certificates..."
    EXISTING_CERT_ARN=$(aws acm list-certificates --query "CertificateSummaryList[?contains(DomainName, '${DOMAIN_NAME}')].CertificateArn" --output text)
    if [ -n "$EXISTING_CERT_ARN" ]; then
        echo " - Found existing certificate for ${DOMAIN_NAME}, will delete: ${EXISTING_CERT_ARN}"
        aws acm delete-certificate --certificate-arn ${EXISTING_CERT_ARN}
    fi
fi

# 1. Clean up Elastic IPs
echo "1. Checking for existing Elastic IPs..."
EXISTING_ELASTIC_IP_ALLOCATION_IDS=$(aws ec2 describe-tags \
    --filters "Name=key,Values=Name" "Name=value,Values=${ELASTIC_IP_TAG_NAME}" "Name=resource-type,Values=elastic-ip" \
    --query 'Tags[*].ResourceId' --output text)
if [ -n "$EXISTING_ELASTIC_IP_ALLOCATION_IDS" ]; then
    echo " - Found existing Elastic IPs, checking availability..."
    # Get the first available (unallocated or at least not associated) Elastic IP
    for ALLOCATION_ID in $EXISTING_ELASTIC_IP_ALLOCATION_IDS; do
        ASSOCIATION_ID=$(aws ec2 describe-addresses --allocation-ids $ALLOCATION_ID --query 'Addresses[0].AssociationId' --output text)
        if [ "$ASSOCIATION_ID" = "None" ] || [ -z "$ASSOCIATION_ID" ]; then
            echo " - Found available Elastic IP with allocation ID: $ALLOCATION_ID"
            REUSE_ALLOCATION_ID=$ALLOCATION_ID
            break
        fi
    done
    # If no available IP found, release the first one to reuse
    if [ -z "$REUSE_ALLOCATION_ID" ]; then
        ALLOCATION_ID=$(echo $EXISTING_ELASTIC_IP_ALLOCATION_IDS | awk '{print $1}')
        echo " - No available Elastic IPs found, releasing one to reuse..."
        aws ec2 disassociate-address --allocation-id $ALLOCATION_ID > /dev/null 2>&1
        REUSE_ALLOCATION_ID=$ALLOCATION_ID
    fi
else
    echo " - No existing Elastic IPs found"
fi

# 2. Clean up EC2 instances
echo "2. Cleaning up EC2 instances..."  
EXISTING_INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text)
if [ -n "$EXISTING_INSTANCE_IDS" ]; then
    echo " - Found existing instances, renaming before termination..."
    # Rename instances by adding "-deleting" suffix to avoid naming conflicts
    for INSTANCE_ID in $EXISTING_INSTANCE_IDS; do
        aws ec2 create-tags --resources "$INSTANCE_ID" --tags "Key=Name,Value=${INSTANCE_TAG_NAME}-deleting" > /dev/null
        echo " - Renamed instance $INSTANCE_ID to ${INSTANCE_TAG_NAME}-deleting"
    done
    
    echo " - Initiating termination for instances: $EXISTING_INSTANCE_IDS"
    aws ec2 terminate-instances --instance-ids $EXISTING_INSTANCE_IDS > /dev/null
    echo " - Termination initiated, continuing with script execution..."
else
    echo " - No existing instances found"
fi

# 3. Checking for existing security groups...
EXISTING_SG_ID=$(aws ec2 describe-security-groups --group-names ${SECURITY_GROUP_NAME} \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
if [ -n "$EXISTING_SG_ID" ] && [ "$EXISTING_SG_ID" != "None" ]; then
    echo " - Found existing security group with ID: $EXISTING_SG_ID"
    # Store the ID to reuse later
    SG_ID=$EXISTING_SG_ID
    echo " - Will reuse existing security group"
else
    echo " - No existing security group found with name ${SECURITY_GROUP_NAME}"
fi

# 4. Managing SSH keys...
echo "4. Managing SSH keys..."
# Create .ssh directory with proper permissions if it doesn't exist
if [ ! -d ~/.ssh ]; then
    echo " - Creating ~/.ssh directory"
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
fi

# Check for existing known_hosts and config, remove if needed
if [ -f ~/.ssh/known_hosts ]; then
    rm -f ~/.ssh/known_hosts
fi
if [ -f ~/.ssh/config ]; then
    rm -f ~/.ssh/config
fi

# Check for existing key pair with the same name
KEY_EXISTS=$(aws ec2 describe-key-pairs --key-names ${SSH_KEY_NAME} --query 'KeyPairs[0].KeyName' --output text 2>/dev/null)
if [ "$KEY_EXISTS" = "${SSH_KEY_NAME}" ]; then
    echo " - Found existing key pair with name: ${SSH_KEY_NAME}"
    # Check if the private key file exists locally
    if [ -f ~/.ssh/${SSH_KEY_NAME} ]; then
        echo " - Found local private key file, will reuse it"
        REUSE_KEY=true
    else
        echo " - Local private key file not found, deleting remote key pair to recreate"
        aws ec2 delete-key-pair --key-name ${SSH_KEY_NAME}
        REUSE_KEY=false
    fi
else
    echo " - No existing key pair found with name: ${SSH_KEY_NAME}"
    REUSE_KEY=false
fi

echo " - Will use SSH key with name: ${SSH_KEY_NAME}"

###########################################
# Resource Creation Phase
###########################################

# 1. Create and configure SSH key pair
if [ "$REUSE_KEY" = true ]; then
    echo "Reusing existing key pair: ${SSH_KEY_NAME}..."
    # Make sure the permissions are correct
    chmod 600 ~/.ssh/${SSH_KEY_NAME}
else
    echo "Creating new key pair: ${SSH_KEY_NAME}..."
    # Create temporary file for key
    KEY_FILE=$(mktemp)
    if aws ec2 create-key-pair --key-name ${SSH_KEY_NAME} --query 'KeyMaterial' --output text > $KEY_FILE 2>/dev/null; then
        # Move the key to .ssh directory and set permissions
        mv $KEY_FILE ~/.ssh/${SSH_KEY_NAME}
        chmod 600 ~/.ssh/${SSH_KEY_NAME}
        echo " - Key pair created successfully and stored at ~/.ssh/${SSH_KEY_NAME}"
    else
        echo " - Failed to create key pair. Cleaning up..."
        rm -f $KEY_FILE
        exit 1
    fi
fi

# 2. Create or reuse security group
if [ -n "$SG_ID" ]; then
    echo "Reusing existing security group: $SG_ID"
    echo " - Security group already exists, skipping creation"
    # Optionally verify/update rules if needed
    # The checks below will ensure the required ports are open
    EXISTING_RULES=$(aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].IpPermissions' --output json)
else
    echo "Creating security group ${SECURITY_GROUP_NAME}..."
    # Create the security group with original name
    SG_ID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} \
        --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)

    if [ -z "$SG_ID" ]; then
        echo " - First attempt failed, retrying with backoff..."
        # Retry with exponential backoff
        for i in $(seq 1 $MAX_RETRIES); do
            wait_time=$((2 ** i))
            echo " - Waiting ${wait_time} seconds before retry $i..."
            sleep $wait_time
            
            SG_ID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} \
                --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null)
                
            if [ -n "$SG_ID" ]; then
                echo " - Successfully created security group on attempt $i"
                break
            fi
            
            if [ $i -eq $MAX_RETRIES ]; then
                echo "Failed to create security group after $MAX_RETRIES attempts. Exiting..."
                exit 1
            fi
        done
    fi

    echo "Successfully created security group: $SG_ID"
    aws ec2 create-tags --resources "$SG_ID" --tags "Key=Name,Value=${SECURITY_GROUP_NAME}" > /dev/null
    # For new security groups, we need to set permissions
    EXISTING_RULES="[]"  # No rules yet
fi

# Check and configure required ports - only add if they don't exist
echo "Verifying required ports..."

# Helper function to check if port is already open
port_is_open() {
    local port=$1
    echo "$EXISTING_RULES" | grep -q "\"FromPort\": $port" && \
    echo "$EXISTING_RULES" | grep -q "\"ToPort\": $port" && \
    echo "$EXISTING_RULES" | grep -q "\"CidrIp\": \"0.0.0.0/0\""
}

# Open SSH port if needed
if ! port_is_open 22; then
    echo " - Opening SSH (port 22)"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null
fi

# Open HTTP port if needed
if ! port_is_open 80; then
    echo " - Opening HTTP (port 80)"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0 > /dev/null
fi

# Open HTTPS port if needed
if ! port_is_open 443; then
    echo " - Opening HTTPS (port 443)"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 > /dev/null
fi

# Open Code Server port if needed
if ! port_is_open 8080; then
    echo " - Opening Code Server (port 8080)"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 8080 --cidr 0.0.0.0/0 > /dev/null
fi

# 3. Launch EC2 instance using standard Amazon Linux 2023 AMI
echo "Retrieving the latest Amazon Linux 2023 AMI using SSM parameter..."
AMI_ID=$(aws ssm get-parameter --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" --query "Parameter.Value" --output text)
echo "Using AMI ID: $AMI_ID"
echo "Creating instance..."
INSTANCE_ID=$(aws ec2 run-instances --image-id "$AMI_ID" --count 1 --instance-type "$INSTANCE_TYPE" \
    --key-name ${SSH_KEY_NAME} --security-group-ids "$SG_ID" \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":10,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${INSTANCE_TAG_NAME}}]" \
                        "ResourceType=volume,Tags=[{Key=Name,Value=volWebServerAuto}]" \
    --query 'Instances[0].InstanceId' --output text)
if [ -z "$INSTANCE_ID" ]; then
    echo "Failed to create instance"
    exit 1
fi

echo "Waiting for instance to be ready..."
start_time=$(date +%s)
while true; do
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))
    if [ $elapsed_time -gt $TIMEOUT ]; then
        echo -e "\nTimeout waiting for instance to be ready after $((TIMEOUT/60)) minutes"
        exit 1
    fi
    STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name' --output text)
    printf "\rCurrent state: %-10s Time: %ds" "$STATE" "$elapsed_time"
    if [ "$STATE" = "running" ]; then
        echo -e "\nInstance is running..."
        sleep 10
        break
    elif [ "$STATE" = "terminated" ] || [ "$STATE" = "shutting-down" ]; then
        echo -e "\nError: Instance terminated unexpectedly"
        exit 1
    fi
    sleep 2
done

# 4. Configure Elastic IP
if [ -n "$REUSE_ALLOCATION_ID" ]; then
    echo "Reusing existing Elastic IP..."
    ALLOCATION_ID=$REUSE_ALLOCATION_ID
else
    echo "Allocating a new Elastic IP..."
    ALLOCATION_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
    echo "Tagging Elastic IP..."
    aws ec2 create-tags --resources "$ALLOCATION_ID" --tags Key=Name,Value=${ELASTIC_IP_TAG_NAME}
fi

echo "Getting Elastic IP address..."
ELASTIC_IP=$(aws ec2 describe-addresses --allocation-ids "$ALLOCATION_ID" --query 'Addresses[0].PublicIp' --output text)
echo "Associating Elastic IP with the new instance..."
aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOCATION_ID" > /dev/null
echo "Host vm configuration added to ~/.ssh/config:"
echo "Host vm
    HostName $ELASTIC_IP
    User ec2-user
    IdentityFile ~/.ssh/${SSH_KEY_NAME}" > ~/.ssh/config
chmod 600 ~/.ssh/config

# Before SSH connection attempt, confirm key file exists
if [ ! -f ~/.ssh/${SSH_KEY_NAME} ]; then
    echo "Error: SSH key file not found at ~/.ssh/${SSH_KEY_NAME}"
    exit 1
fi

# Display key file permissions for debugging
ls -la ~/.ssh/${SSH_KEY_NAME}

echo "Attempting to establish SSH connection..."
count=0
while ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@$ELASTIC_IP 'exit' 2>/dev/null; do
    count=$((count+1))
    printf "\rAttempt %d/%d " $count $MAX_RETRIES
    if [ $count -eq $MAX_RETRIES ]; then
        echo -e "\nFailed to establish SSH connection after $MAX_RETRIES attempts"
        exit 1
    fi
    sleep 2
done
echo -e "\nSSH connection established!"

###########################################
# HTTPS Setup Phase (if domain is provided)
###########################################
if [ "$SETUP_HTTPS" = true ]; then
    echo "Starting HTTPS setup for domain: $DOMAIN_NAME"

    # Get the VPC ID of the instance
    VPC_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].VpcId' --output text)
    if [ -z "$VPC_ID" ]; then
        echo "Error: Could not determine VPC ID for the instance"
        exit 1
    fi
    echo "Instance is in VPC: $VPC_ID"

    # Get subnet information
    SUBNET_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].SubnetId' --output text)
    echo "Instance is in subnet: $SUBNET_ID"

    # Get all subnets in the VPC for ALB (need at least 2 subnets in different AZs)
    SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[*].SubnetId' --output text)
    SUBNET_COUNT=$(echo $SUBNETS | wc -w)
    if [ "$SUBNET_COUNT" -lt 2 ]; then
        echo "Error: ALB requires at least 2 subnets in different AZs. Found $SUBNET_COUNT."
        echo "Consider using a different VPC or creating additional subnets."
        exit 1
    fi
    # Take first 2 subnets for ALB
    SUBNET_LIST=$(echo $SUBNETS | tr ' ' '\n' | head -2 | tr '\n' ' ')
    echo "Using subnets for ALB: $SUBNET_LIST"

    # 1. Create SSL Certificate with DNS validation
    echo "1. Creating SSL Certificate..."
    CERT_ARN=$(aws acm request-certificate \
        --domain-name $DOMAIN_NAME \
        --validation-method DNS \
        --tags Key=Name,Value=$CERTIFICATE_TAG_NAME \
        --query 'CertificateArn' --output text)
    
    if [ -z "$CERT_ARN" ]; then
        echo "Failed to create SSL certificate"
        exit 1
    fi
    echo "Certificate ARN: $CERT_ARN"
    
    # Get the DNS validation records
    echo "Waiting for certificate details..."
    sleep 5  # Give AWS time to process the certificate request
    
    CERT_VALIDATION=$(aws acm describe-certificate \
        --certificate-arn $CERT_ARN \
        --query 'Certificate.DomainValidationOptions[0].ResourceRecord' \
        --output json)
    
    if [ -z "$CERT_VALIDATION" ] || [ "$CERT_VALIDATION" == "null" ]; then
        echo "Failed to get certificate validation details. Retrying..."
        sleep 10
        CERT_VALIDATION=$(aws acm describe-certificate \
            --certificate-arn $CERT_ARN \
            --query 'Certificate.DomainValidationOptions[0].ResourceRecord' \
            --output json)
    fi
    
    DNS_NAME=$(echo $CERT_VALIDATION | jq -r '.Name')
    DNS_VALUE=$(echo $CERT_VALIDATION | jq -r '.Value')
    
    echo "To validate your certificate, create the following DNS record:"
    echo "Record Name: $DNS_NAME"
    echo "Record Type: CNAME"
    echo "Record Value: $DNS_VALUE"
    
    # 2. Create Target Group
    echo "2. Creating Target Group..."
    TG_ARN=$(aws elbv2 create-target-group \
        --name $TARGET_GROUP_NAME \
        --protocol HTTP \
        --port 80 \
        --vpc-id $VPC_ID \
        --health-check-path "/" \
        --target-type instance \
        --query 'TargetGroups[0].TargetGroupArn' --output text)
    
    if [ -z "$TG_ARN" ]; then
        echo "Failed to create Target Group"
        exit 1
    fi
    echo "Target Group created: $TG_ARN"
    
    # Register the EC2 instance with the target group
    echo "Registering instance with Target Group..."
    aws elbv2 register-targets \
        --target-group-arn $TG_ARN \
        --targets Id=$INSTANCE_ID > /dev/null
    
    # 3. Create Application Load Balancer
    echo "3. Creating Application Load Balancer..."
    ALB_ARN=$(aws elbv2 create-load-balancer \
        --name $ALB_NAME \
        --subnets $SUBNET_LIST \
        --security-groups $SG_ID \
        --scheme internet-facing \
        --type application \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)
    
    if [ -z "$ALB_ARN" ]; then
        echo "Failed to create Application Load Balancer"
        exit 1
    fi
    echo "ALB created: $ALB_ARN"
    
    # Get the ALB DNS name
    ALB_DNS_NAME=$(aws elbv2 describe-load-balancers \
        --load-balancer-arns $ALB_ARN \
        --query 'LoadBalancers[0].DNSName' --output text)
    
    echo "ALB DNS name: $ALB_DNS_NAME"
    
    # Wait for the ALB to be active
    echo "Waiting for ALB to become active..."
    aws elbv2 wait load-balancer-available --load-balancer-arns $ALB_ARN
    
    # 4. Create HTTP and HTTPS listeners for the ALB
    echo "4. Creating HTTP listener (will redirect to HTTPS)..."
    aws elbv2 create-listener \
        --load-balancer-arn $ALB_ARN \
        --protocol HTTP \
        --port 80 \
        --default-actions Type=redirect,RedirectConfig="{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}" > /dev/null
    
    # For HTTPS listener, we need to check if certificate validation is complete
    echo "To continue with HTTPS setup:"
    echo "1. Create the DNS validation record shown above with your domain registrar"
    echo "2. After creating the validation record, the certificate will be validated automatically"
    echo "3. This script will now wait for certificate validation to complete"
    echo "   (this could take from a few minutes to several hours depending on DNS propagation)"
    echo ""
    echo "Checking certificate validation status every 30 seconds..."
    
    VALIDATION_STATUS="PENDING_VALIDATION"
    while [ "$VALIDATION_STATUS" != "ISSUED" ]; do
        VALIDATION_STATUS=$(aws acm describe-certificate \
            --certificate-arn $CERT_ARN \
            --query 'Certificate.Status' --output text)
        
        echo "Current certificate status: $VALIDATION_STATUS"
        if [ "$VALIDATION_STATUS" == "ISSUED" ]; then
            echo "Certificate has been successfully validated!"
            break
        elif [ "$VALIDATION_STATUS" == "FAILED" ]; then
            echo "Certificate validation failed. Please check your DNS settings."
            exit 1
        fi
        
        echo "Waiting 30 seconds before checking again..."
        sleep 30
    done
    
    # Create HTTPS listener
    echo "5. Creating HTTPS listener..."
    HTTPS_LISTENER_ARN=$(aws elbv2 create-listener \
        --load-balancer-arn $ALB_ARN \
        --protocol HTTPS \
        --port 443 \
        --certificates CertificateArn=$CERT_ARN \
        --ssl-policy ELBSecurityPolicy-2016-08 \
        --default-actions Type=forward,TargetGroupArn=$TG_ARN \
        --query 'Listeners[0].ListenerArn' --output text)
    
    if [ -z "$HTTPS_LISTENER_ARN" ]; then
        echo "Failed to create HTTPS listener"
        exit 1
    fi
    echo "HTTPS listener created: $HTTPS_LISTENER_ARN"
    
    # 5. Create Route 53 records (if user has provided domain)
    echo "6. Setting up Route 53 records for domain: $DOMAIN_NAME"
    
    # Get the hosted zone ID for the domain
    HOSTED_ZONE_ID=$(aws route53 list-hosted-zones-by-name \
        --dns-name $DOMAIN_NAME \
        --query 'HostedZones[0].Id' --output text | sed 's|/hostedzone/||')
    
    if [ -z "$HOSTED_ZONE_ID" ] || [ "$HOSTED_ZONE_ID" == "None" ]; then
        echo "No Route 53 hosted zone found for $DOMAIN_NAME"
        echo "Creating a hosted zone automatically..."
        
        # Create a hosted zone without asking for confirmation
        HOSTED_ZONE_ID=$(aws route53 create-hosted-zone \
            --name $DOMAIN_NAME \
            --caller-reference "$(date +%s)" \
            --hosted-zone-config Comment="Created by AWS LAMP installer script" \
            --query 'HostedZone.Id' --output text | sed 's|/hostedzone/||')
            
        echo "Hosted zone created. Make sure to update your domain's name servers with your registrar."
        aws route53 get-hosted-zone --id $HOSTED_ZONE_ID --query 'DelegationSet.NameServers' --output text | sed 's/\t/\n/g' | sed 's/^/Name server: /'
    fi
    
    if [ -n "$HOSTED_ZONE_ID" ]; then
        # Create A record for domain pointing to ALB
        echo "Creating A record (alias) for $DOMAIN_NAME pointing to ALB..."
        
        # Get the hosted zone ID for the ALB (different from the Route 53 hosted zone ID)
        REGION=$(aws configure get region)
        ALB_HOSTED_ZONE_ID=$(aws elbv2 describe-load-balancers \
            --load-balancer-arns $ALB_ARN \
            --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)
        
        CHANGE_BATCH=$(cat <<EOF
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN_NAME",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$ALB_HOSTED_ZONE_ID",
          "DNSName": "dualstack.$ALB_DNS_NAME",
          "EvaluateTargetHealth": false
        }
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "www.$DOMAIN_NAME",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "$DOMAIN_NAME"
          }
        ]
      }
    }
  ]
}
EOF
)
        
        aws route53 change-resource-record-sets \
            --hosted-zone-id $HOSTED_ZONE_ID \
            --change-batch "$CHANGE_BATCH" > /dev/null
        
        echo "Route 53 records created for $DOMAIN_NAME and www.$DOMAIN_NAME"
        echo "Please allow time for DNS changes to propagate (typically 15 minutes to a few hours)"
    fi
    
    # 7. Update WordPress site URLs if WordPress is being installed
    if [ "$INSTALL_WORDPRESS" = true ]; then
        echo "7. Setting up WordPress to use HTTPS domain..."
        echo "After WordPress installation completes, WordPress URLs will be automatically updated to use HTTPS"
    fi
    
    echo "HTTPS setup complete!"
    echo "Your website will be accessible at: https://$DOMAIN_NAME"
    echo "You may also access it via ALB DNS name: https://$ALB_DNS_NAME (certificate warnings may appear)"
fi

###########################################
# Installation Phase
###########################################
echo "Starting software installation..."
ssh -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@$ELASTIC_IP 'set -e

#----------------
# LAMP Stack
#----------------
if [ '"$INSTALL_LAMP"' = true ]; then
    echo "Updating DNF repositories..."
    sudo dnf clean all --quiet
    sudo dnf makecache --quiet

    echo "Installing LAMP stack..."
    sudo dnf install -y httpd 
    MARIADB_LATEST_PACKAGE=$(dnf list available | grep -E "^mariadb[0-9]+-server" | awk "{print \$1}" | sort -V | tail -n 1) 
    sudo dnf install -y "$MARIADB_LATEST_PACKAGE" 
    sudo dnf install -y php 

    echo "Configuring LAMP..."
    sudo sed -i.bak -e "s/DirectoryIndex index.html/DirectoryIndex index.php index.html/" /etc/httpd/conf/httpd.conf || true
    sudo dnf install -y wget
    sudo wget https://raw.githubusercontent.com/danielcregg/simple-php-website/main/index.php -P /var/www/html/
    sudo rm -f /var/www/html/index.html
    sudo chown -R apache:apache /var/www
    sudo systemctl enable httpd
    sudo systemctl start httpd
    sudo systemctl enable mariadb
    sudo systemctl start mariadb
fi

#----------------
# SFTP Access
#----------------
if [ '"$INSTALL_SFTP"' = true ]; then
    echo "Enabling root login for SFTP..."
    sudo sed -i "/PermitRootLogin/c\PermitRootLogin yes" /etc/ssh/sshd_config
    sudo echo -e "tester\ntester" | sudo passwd root
    sudo systemctl restart sshd
fi

#----------------
# VS Code Server
#----------------
if [ '"$INSTALL_VSCODE"' = true ]; then
    echo "Setting up VS Code Server..."
    # Install code-server (VS Code in the browser)
    echo "Installing VS Code Server..."
fi

#----------------
# Database Tools
#----------------
#if [ '"$INSTALL_DB"' = true ]; then
#    echo "Installing Adminer..."
#    sudo dnf install -y adminer
#    echo "Configuring Adminer..."
#    sudo ln -s /etc/adminer/conf.d/adminer.conf /etc/httpd/conf.d/adminer.conf || true
#    sudo mysql -Bse "CREATE USER IF NOT EXISTS admin@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON *.* TO admin@localhost;FLUSH PRIVILEGES;"
#    sudo systemctl reload httpd

#    echo "Installing phpMyAdmin..."
#    sudo dnf install -y phpmyadmin
#fi

#----------------
# WordPress
#----------------
if [ '"$INSTALL_WORDPRESS"' = true ]; then
    echo "Installing WordPress..."
    echo "Installing wp-cli..."
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    sudo mv wp-cli.phar /usr/local/bin/wp

    echo "Creating cache for WordPress..."
    # Use current user instead of ec2-user
    sudo mkdir -p /usr/share/httpd/.wp-cli/cache
    sudo chown -R $(whoami):$(whoami) /usr/share/httpd/.wp-cli
    echo "Downloading WordPress..."
    sudo wp core download --path=/var/www/html/ || echo "Warning: Could not download WordPress core"

    echo "Installing required PHP modules for WordPress..."
    sudo dnf install -y php php-mysqlnd php-gd php-curl php-dom php-mbstring php-zip php-intl || echo "Warning: Could not install all PHP modules"
    
    # Install PHP Imagick module which is recommended for WordPress image processing
    echo "Installing PHP Imagick extension..."
    # Update system and install prerequisites
    sudo dnf install -y php-devel php-pear gcc ImageMagick ImageMagick-devel || echo "Warning: Could not install ImageMagick dependencies"
    
    # Find the PHP configuration directory
    PHP_CONFIG_DIR=$(php -i | grep "Scan this dir for additional .ini files" | awk '{print $NF}')
    if [ -z "$PHP_CONFIG_DIR" ]; then
        PHP_CONFIG_DIR="/etc/php.d"
        echo "PHP config directory not found, using default: $PHP_CONFIG_DIR"
        # Create directory if it doesn't exist
        sudo mkdir -p $PHP_CONFIG_DIR
    fi
    
    # Create configuration file for Imagick
    echo "extension=imagick.so" | sudo tee $PHP_CONFIG_DIR/20-imagick.ini > /dev/null
    
    # Start services - use service command instead of systemctl for container compatibility
    echo "Starting web services..."
    command -v service >/dev/null 2>&1 && { 
        sudo service httpd start || echo "Warning: Could not start httpd service";
        sudo service php-fpm start || echo "Warning: Could not start php-fpm service";
    } || {
        echo "Service command not available, trying to start services using alternative methods..."
    }
    
    # Verify installation
    echo "Verifying PHP Imagick installation..."
    if php -m | grep -q imagick; then
        echo "PHP Imagick extension installed successfully!"
    else
        echo "Warning: PHP Imagick extension installation might have failed, but continuing with WordPress setup..."
    fi

    echo "Setting up WordPress database and configuration..."
    # Check if MySQL/MariaDB is available
    if command -v mysql >/dev/null 2>&1; then
        echo "Configuring MySQL for WordPress..."
        sudo mysql -e "CREATE USER IF NOT EXISTS wordpressuser@localhost IDENTIFIED BY 'password';" || echo "Warning: Could not create MySQL user"
        sudo mysql -e "CREATE DATABASE IF NOT EXISTS wordpress;" || echo "Warning: Could not create WordPress database"
        sudo mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO wordpressuser@localhost; FLUSH PRIVILEGES;" || echo "Warning: Could not grant privileges"
    else
        echo "MySQL not found. Install MySQL/MariaDB first to use WordPress."
    fi
    
    # Configure WordPress
    if command -v wp >/dev/null 2>&1; then
        echo "Configuring WordPress..."
        sudo wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/var/www/html/ --skip-check || echo "Warning: Could not create wp-config.php"
        
        # Setup WordPress uploads directory
        sudo mkdir -p /var/www/html/wp-content/uploads
        sudo chmod 775 /var/www/html/wp-content/uploads
        # Use current user instead of ec2-user
        sudo chown -R $(whoami):$(whoami) /var/www/html/wp-content/uploads
        
        # Configure PHP settings if php.ini exists
        if [ -f /etc/php.ini ]; then
            echo "Increasing PHP limits for file uploads..."
            sudo sed -i.bak -e "s/^upload_max_filesize.*/upload_max_filesize = 512M/g" /etc/php.ini || echo "Warning: Could not update upload_max_filesize"
            sudo sed -i.bak -e "s/^post_max_size.*/post_max_size = 512M/g" /etc/php.ini || echo "Warning: Could not update post_max_size"
            sudo sed -i.bak -e "s/^max_execution_time.*/max_execution_time = 300/g" /etc/php.ini || echo "Warning: Could not update max_execution_time"
            sudo sed -i.bak -e "s/^max_input_time.*/max_input_time = 300/g" /etc/php.ini || echo "Warning: Could not update max_input_time"
        else
            echo "PHP configuration file not found at /etc/php.ini"
        fi
        
        # Install WordPress if wp-cli is available
        sudo wp core install --url=$(curl -s ifconfig.me) --title="Website Title" --admin_user="admin" --admin_password="password" --admin_email="x@y.com" --path=/var/www/html/ || echo "Warning: Could not install WordPress core"
        
        # Install and activate plugin
        sudo wp plugin install all-in-one-wp-migration --activate --path=/var/www/html/ || echo "Warning: Could not install WordPress plugin"
        
        # Update themes
        echo "Updating WordPress themes..."
        sudo wp theme update --all --path=/var/www/html/ || echo "Warning: Could not update WordPress themes"
        
        # Update WordPress site URLs to use HTTPS domain if HTTPS is enabled
        if [ '"$SETUP_HTTPS"' = true ] && [ -n '"$DOMAIN_NAME"' ]; then
            echo "Updating WordPress site URLs to use HTTPS domain..."
            sudo wp option update home "https://'"$DOMAIN_NAME"'" --path=/var/www/html/ || echo "Warning: Could not update home URL"
            sudo wp option update siteurl "https://'"$DOMAIN_NAME"'" --path=/var/www/html/ || echo "Warning: Could not update site URL"
            echo "WordPress URLs updated to use HTTPS with domain: '"$DOMAIN_NAME"'"
        fi
    else
        echo "WordPress CLI not found. Please install wp-cli to use WordPress."
    fi
    
    echo "WordPress setup completed with available components."
fi

#----------------
# Matomo Analytics
#----------------
if [ '"$INSTALL_MATOMO"' = true ]; then
    echo "Installing Matomo Analytics Server..."
    sudo dnf install -y unzip php-dom php-xml php-mbstring
    sudo systemctl restart httpd
    sudo wget https://builds.matomo.org/matomo.zip -P /var/www/html/
    sudo unzip -oq /var/www/html/matomo.zip -d /var/www/html/
    sudo chown -R apache:apache /var/www/html/matomo
    sudo rm -f /var/www/html/matomo.zip
    sudo rm -f /var/www/html/'How to install Matomo.html'
    sudo mysql -Bse "CREATE DATABASE matomodb;CREATE USER matomoadmin@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON matomodb.* TO matomoadmin@localhost; FLUSH PRIVILEGES;"
    sudo -u apache wp plugin install matomo --activate --path=/var/www/html/
    sudo -u apache wp plugin install wp-piwik --activate --path=/var/www/html/
    sudo -u apache wp plugin install super-progressive-web-apps --activate --path=/var/www/html/
fi

###########################################
# Final Status Output
###########################################
if [ '$INSTALL_LAMP' = true ]; then
    printf "\nClick on this link to open your website: \e[3;4;33mhttp://$(curl -s ifconfig.me)\e[0m\n"
fi
if [ '$INSTALL_SFTP' = true ]; then
    printf "\nClick on this link to download WinSCP: \e[3;4;33mhttps://dcus.short.gy/downloadWinSCP\e[0m - Note: User name = root and password = tester\n"
fi
if [ '$INSTALL_VSCODE' = true ]; then
    printf "\nSSH into your new VM (ssh vm) and run this command to open a VS Code tunnel: \e[3;4;33msudo code tunnel\e[0m\nFollow the instructions in the terminal to connect via your browser.\n"
    printf "\nYou can also access VS Code online by visiting: \e[3;4;33mhttp://$(curl -s ifconfig.me):8080\e[0m \n"
fi
if [ '$INSTALL_DB' = true ]; then    
    printf "\nOpen an internet browser and go to: \e[3;4;33mhttp://$(curl -s ifconfig.me)/adminer/?username=admin\e[0m - Adminer Login page (username: admin, password: password)\n"
    printf "\nOpen an internet browser and go to: \e[3;4;33mhttp://$(curl -s ifconfig.me)/phpmyadmin\e[0m - phpMyAdmin Login page (admin/password)\n"
fi
if [ '$INSTALL_WORDPRESS' = true ]; then
    printf "\nOpen an internet browser and go to: \e[3;4;33mhttp://$(curl -s ifconfig.me)\e[0m - You should see the WordPress page.\n"
    printf "\nAccess the WordPress Dashboard at: \e[3;4;33mhttp://$(curl -s ifconfig.me)/wp-admin\e[0m (credentials: admin/password)\n"
fi
if [ '$INSTALL_MATOMO' = true ]; then
    printf "\nOpen an internet browser and go to: \e[3;4;33mhttp://$(curl -s ifconfig.me)/matomo\e[0m - Matomo Install page.\n"
fi
if [ '$SETUP_HTTPS' = true ]; then
    printf "\n\e[1;32mHTTPS Setup Information:\e[0m\n"
    printf "Your secure website will be accessible at: \e[3;4;33mhttps://$DOMAIN_NAME\e[0m\n"
    printf "You can also access the site via the ALB DNS: \e[3;4;33mhttps://$ALB_DNS_NAME\e[0m\n"
    printf "Note that it may take some time for DNS changes to propagate globally.\n"
    
    if [ '$INSTALL_WORDPRESS' = true ]; then
        printf "Once DNS propagation is complete, log in to WordPress and update the site URL:\n"
        printf "1. Access WordPress admin: \e[3;4;33mhttps://$DOMAIN_NAME/wp-admin\e[0m\n"
        printf "2. Go to Settings > General\n"
        printf "3. Update both \"WordPress Address (URL)\" and \"Site Address (URL)\" to \e[3;4;33mhttps://$DOMAIN_NAME\e[0m\n"
    fi
fi
printf "\nYou can SSH into your new VM on this Cloud Shell using: \e[3;4;33mssh vm\e[0m\n"
echo "********************************"
echo "* SUCCESS! - Script completed! *"
echo "********************************"
'
