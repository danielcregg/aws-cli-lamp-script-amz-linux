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

# Display an animated spinner with a message (call in a loop)
show_spinner() {
    local message="$1"
    echo -en "\r\033[K$message"
    for cursor in '/' '-' '\' '|'; do
        echo -en "\b$cursor"
        sleep 0.5
    done
}

# Retry a command with exponential backoff (base 5s * 2^attempt)
# Usage: retry_command "aws ec2 ..." "create instance" 3
retry_command() {
    local cmd="$1"
    local description="$2"
    local max_attempts="${3:-$MAX_RETRIES}"
    local attempt=1
    local output=""

    echo "Attempting to $description..."
    while [ "$attempt" -le "$max_attempts" ]; do
        echo " - Attempt $attempt/$max_attempts"
        if output=$(eval "$cmd" 2>&1); then
            echo " - Success: $description"
            echo "$output"
            return 0
        fi

        local wait_time=$((2 ** (attempt - 1) * 5))
        echo " - Failed. Waiting ${wait_time}s before retrying..."
        sleep "$wait_time"
        attempt=$((attempt + 1))
    done

    echo "Failed to $description after $max_attempts attempts. Exiting..."
    echo "Last error: $output"
    return 1
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
printf "\e[3;4;31mStarting cleanup of AWS resources...\e[0m\n"

# 1. Clean up Elastic IPs — disassociate from old instances so we can reuse
echo "1. Checking for existing Elastic IPs..."
EXISTING_ELASTIC_IP_ALLOCATION_IDS=$(aws ec2 describe-tags \
    --filters "Name=key,Values=Name" "Name=value,Values=${ELASTIC_IP_TAG_NAME}" "Name=resource-type,Values=elastic-ip" \
    --query 'Tags[*].ResourceId' --output text) || true
if [ -n "$EXISTING_ELASTIC_IP_ALLOCATION_IDS" ]; then
    echo " - Found existing Elastic IPs, checking availability..."
    for ALLOCATION_ID in $EXISTING_ELASTIC_IP_ALLOCATION_IDS; do
        ASSOC_ID=$(aws ec2 describe-addresses --allocation-ids "$ALLOCATION_ID" \
            --query 'Addresses[0].AssociationId' --output text) || true
        if [ -z "$ASSOC_ID" ] || [ "$ASSOC_ID" = "None" ]; then
            # Already free — reuse it directly
            echo " - Found available Elastic IP: $ALLOCATION_ID"
            REUSE_ALLOCATION_ID=$ALLOCATION_ID
            break
        else
            # Disassociate from the old instance so we can reuse it
            echo " - Disassociating Elastic IP $ALLOCATION_ID from old instance..."
            aws ec2 disassociate-address --association-id "$ASSOC_ID" > /dev/null 2>&1 || true
            REUSE_ALLOCATION_ID=$ALLOCATION_ID
            break
        fi
    done
else
    echo " - No existing Elastic IPs found"
fi

# 2. Clean up EC2 instances
echo "2. Cleaning up EC2 instances..."  
EXISTING_INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text) || true
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

# 3. Check for existing security group to reuse (avoids duplicate creation errors)
echo "3. Checking for existing security groups..."
EXISTING_SG_ID=$(aws ec2 describe-security-groups --group-names "${SECURITY_GROUP_NAME}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null) || true
if [ -n "$EXISTING_SG_ID" ] && [ "$EXISTING_SG_ID" != "None" ]; then
    echo " - Found existing security group with ID: $EXISTING_SG_ID"
    SG_ID="$EXISTING_SG_ID"
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
KEY_EXISTS=$(aws ec2 describe-key-pairs --key-names "${SSH_KEY_NAME}" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null) || true
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

# 2. Create or reuse security group (ports are verified/added below regardless)
if [ -n "${SG_ID:-}" ]; then
    echo "Reusing existing security group: $SG_ID"
    echo " - Security group already exists, skipping creation"
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
fi

# Ensure all required ports are open (idempotent — skips ports already open)
echo "Verifying required ports..."

# Open a port if it isn't already allowed for 0.0.0.0/0.
# Uses authorize-security-group-ingress which is a no-op error when the rule exists,
# so we just suppress that specific error.
open_port_if_needed() {
    local port="$1"
    local label="$2"
    if ! aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port "$port" --cidr 0.0.0.0/0 > /dev/null 2>&1; then
        echo " - $label (port $port) already open"
    else
        echo " - Opened $label (port $port)"
    fi
}

open_port_if_needed 22   "SSH"
open_port_if_needed 80   "HTTP"
open_port_if_needed 443  "HTTPS"
open_port_if_needed 8080 "Code Server"

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
if [ -n "${REUSE_ALLOCATION_ID:-}" ]; then
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

# Verify key file permissions before connecting
ls -la ~/.ssh/${SSH_KEY_NAME}

# Wait for SSH to become available on the new instance.
# StrictHostKeyChecking=no is used because this is a freshly created instance
# with no prior host key — the Elastic IP may have been reused from a previous run.
echo "Attempting to establish SSH connection..."
count=0
while ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@"$ELASTIC_IP" 'exit' 2>/dev/null; do
    count=$((count+1))
    printf "\rAttempt %d/%d " "$count" "$MAX_RETRIES"
    if [ "$count" -eq "$MAX_RETRIES" ]; then
        echo -e "\nFailed to establish SSH connection after $MAX_RETRIES attempts"
        exit 1
    fi
    sleep 2
done
echo -e "\nSSH connection established!"

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
    sudo systemctl enable --now httpd
    sudo systemctl enable --now mariadb
fi

#----------------
# SFTP Access
#----------------
if [ '"$INSTALL_SFTP"' = true ]; then
    echo "Enabling root login for SFTP..."
    sudo sed -i "/PermitRootLogin/c\PermitRootLogin yes" /etc/ssh/sshd_config
    echo "root:tester" | sudo chpasswd
    sudo systemctl restart sshd
fi

#----------------
# VS Code Server
#----------------
if [ '"$INSTALL_VSCODE"' = true ]; then
    echo "Setting up VS Code Server..."
    # TODO: Add VS Code Server installation commands
    echo " - VS Code Server installation not yet implemented, skipping..."
fi

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
    sudo mkdir -p /usr/share/httpd/.wp-cli/cache
    sudo chown -R apache:apache /usr/share/httpd/.wp-cli
    echo "Downloading WordPress..."
    sudo -u apache wp core download --path=/var/www/html/

    echo "Installing required PHP modules for WordPress..."
    sudo dnf install -y php php-mysqlnd php-gd php-curl php-dom php-mbstring php-zip php-intl
    
    # Install PHP Imagick module (recommended for WordPress image processing).
    # AL2023 does not provide a pre-built php-imagick package, so we compile from source.
    sudo dnf check-release-update || true
    sudo dnf upgrade --releasever=latest -y
    sudo dnf install -y php-devel php-pear gcc ImageMagick ImageMagick-devel

    # Download, compile and install Imagick
    pecl download Imagick
    tar -xf imagick*.tgz
    IMAGICK_DIR=$(find . -type d -name "imagick*" | head -1)
    cd "$IMAGICK_DIR"
    phpize
    ./configure
    make
    sudo make install

    # Create configuration file
    echo "extension=imagick.so" | sudo tee /etc/php.d/25-imagick.ini > /dev/null

    # Restart Apache to load the new extension (php-fpm may not be active on AL2023)
    sudo systemctl restart php-fpm 2>/dev/null || true
    sudo systemctl restart httpd

    # Verify installation
    php -m | grep -i imagick

    # Clean up
    cd ..
    rm -rf imagick*

    echo "php-imagick installation complete!"

    echo "Configuring WordPress..."
    # Create DB user with full privileges first so wp-cli can create the database,
    # then revoke and restrict to only the wordpress database.
    sudo mysql -Bse "CREATE USER IF NOT EXISTS wordpressuser@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON *.* TO wordpressuser@localhost;FLUSH PRIVILEGES;"
    sudo -u apache wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/var/www/html/
    sudo -u apache wp db create --path=/var/www/html/
    sudo mysql -Bse "REVOKE ALL PRIVILEGES, GRANT OPTION FROM wordpressuser@localhost;GRANT ALL PRIVILEGES ON wordpress.* TO wordpressuser@localhost;FLUSH PRIVILEGES;"
    sudo mkdir -p /var/www/html/wp-content/uploads
    sudo chmod 775 /var/www/html/wp-content/uploads
    sudo chown apache:apache /var/www/html/wp-content/uploads
    echo "Increasing PHP limits for file uploads..."
    sudo sed -i.bak -e "s/^upload_max_filesize.*/upload_max_filesize = 512M/g" /etc/php.ini
    sudo sed -i.bak -e "s/^post_max_size.*/post_max_size = 512M/g" /etc/php.ini
    sudo sed -i.bak -e "s/^max_execution_time.*/max_execution_time = 300/g" /etc/php.ini
    sudo sed -i.bak -e "s/^max_input_time.*/max_input_time = 300/g" /etc/php.ini
    sudo systemctl restart httpd
    sudo -u apache wp core install --url=$(curl -s ifconfig.me) --title="Website Title" --admin_user="admin" --admin_password="password" --admin_email="x@y.com" --path=/var/www/html/
    sudo -u apache wp plugin list --status=inactive --field=name --path=/var/www/html/ | xargs --replace=% sudo -u apache wp plugin delete % --path=/var/www/html/
    sudo -u apache wp theme list --status=inactive --field=name --path=/var/www/html/ | xargs --replace=% sudo -u apache wp theme delete % --path=/var/www/html/
    sudo -u apache wp plugin install all-in-one-wp-migration --activate --path=/var/www/html/
    
    echo "Updating WordPress themes..."
    sudo -u apache wp theme update --all --path=/var/www/html/
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
printf "\nYou can SSH into your new VM on this Cloud Shell using: \e[3;4;33mssh vm\e[0m\n"
echo "********************************"
echo "* SUCCESS! - Script completed! *"
echo "********************************"
'
