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
###########################################

###########################################
# Configuration Variables
###########################################
TIMEOUT=120                    # Maximum wait time for instance startup (seconds)
MAX_RETRIES=3                  # Maximum retry attempts for operations
INSTANCE_TYPE="t2.medium"      # AWS instance type
SSH_KEY_NAME="key_WebServerAuto"
SECURITY_GROUP_NAME="webServerSecurityGroup"
INSTANCE_TAG_NAME="myWebServerAuto"
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

# 1. Clean up Elastic IPs
echo "1. Cleaning up Elastic IPs..."
EXISTING_ELASTIC_IP_ALLOCATION_IDS=$(aws ec2 describe-tags \
    --filters "Name=key,Values=Name" "Name=value,Values=${ELASTIC_IP_TAG_NAME}" "Name=resource-type,Values=elastic-ip" \
    --query 'Tags[*].ResourceId' --output text)
if [ -n "$EXISTING_ELASTIC_IP_ALLOCATION_IDS" ]; then
    echo " - Found existing Elastic IPs, releasing..."
    for ALLOCATION_ID in $EXISTING_ELASTIC_IP_ALLOCATION_IDS; do
        aws ec2 release-address --allocation-id $ALLOCATION_ID
        echo " - Released Elastic IP with allocation ID: $ALLOCATION_ID"
    done
else
    echo " - No existing Elastic IPs found"
fi

# 2. Clean up EC2 instances
echo "2. Cleaning up EC2 instances..."
EXISTING_INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=${INSTANCE_TAG_NAME}" "Name=instance-state-name,Values=running,pending,stopping,stopped" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text)
if [ -n "$EXISTING_INSTANCE_IDS" ]; then
    echo " - Found existing instances, terminating..."
    aws ec2 terminate-instances --instance-ids $EXISTING_INSTANCE_IDS > /dev/null
    echo " - Termination initiated for instances: $EXISTING_INSTANCE_IDS"
    echo " - Waiting for instances to terminate..."
    while true; do
        STATUS=$(aws ec2 describe-instances --instance-ids $EXISTING_INSTANCE_IDS --query 'Reservations[*].Instances[*].[InstanceId,State.Name]' --output text)
        echo -en "\r\033[K - Current status:"
        while IFS=$'\t' read -r id state; do
            printf " %s: %-15s" "$id" "$state"
        done <<< "$STATUS"
        if ! echo "$STATUS" | grep -qv "terminated"; then
            echo -e "\n - All instances terminated successfully"
            break
        fi
        for cursor in '/' '-' '\' '|'; do
            echo -en "\b$cursor"
            sleep 0.5
        done
    done
else
    echo " - No existing instances found"
fi

# 3. Clean up security groups
echo "3. Cleaning up security groups..."
EXISTING_SG_ID=$(aws ec2 describe-security-groups --group-names ${SECURITY_GROUP_NAME} \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
if [ -n "$EXISTING_SG_ID" ] && [ "$EXISTING_SG_ID" != "None" ]; then
    echo " - Found existing security group, checking dependencies..."
    while true; do
        DEPENDENT_INSTANCES=$(aws ec2 describe-instances --filters "Name=instance.group-id,Values=$EXISTING_SG_ID" \
            "Name=instance-state-name,Values=running,pending,stopping,stopped,shutting-down" \
            --query 'Reservations[*].Instances[*].InstanceId' --output text)
        if [ -z "$DEPENDENT_INSTANCES" ]; then
            break
        fi
        echo " - Waiting for dependent instances to terminate..."
        sleep 5
    done
    for i in 1 2 3; do
        if aws ec2 delete-security-group --group-id $EXISTING_SG_ID 2>/dev/null; then
            echo " - Security group deleted successfully"
            break
        else
            if [ $i -eq 3 ]; then
                echo "Failed to delete security group after 3 attempts. Please check AWS Console and try again."
                exit 1
            fi
            echo " - Deletion attempt $i failed, waiting ${i}0 seconds..."
            sleep $((i * 10))
        fi
    done
else
    echo " - No existing security group found"
fi

# 4. Clean up SSH keys
echo "4. Cleaning up SSH keys..."
if aws ec2 describe-key-pairs --key-name ${SSH_KEY_NAME} >/dev/null 2>&1; then
    echo " - Found existing key pair, removing..."
    aws ec2 delete-key-pair --key-name ${SSH_KEY_NAME} > /dev/null
    rm -f ~/.ssh/${SSH_KEY_NAME}* ~/.ssh/known_hosts* ~/.ssh/config
    echo " - Removed key pair and local SSH files"
    sleep 2
else
    echo " - No existing key pair found"
fi

###########################################
# Resource Creation Phase
###########################################

# 1. Create security group and configure ports
echo "Creating new security group..."
for i in 1 2 3; do
    SG_ID=$(aws ec2 create-security-group --group-name ${SECURITY_GROUP_NAME} \
        --description "Web Server security group" --query 'GroupId' --output text 2>/dev/null) && break
    echo " - Creation attempt $i failed, waiting ${i}0 seconds..."
    sleep $((i * 10))
    if [ $i -eq 3 ]; then
        echo "Failed to create security group after 3 attempts. Exiting..."
        exit 1
    fi
done
echo "Successfully created security group: $SG_ID"
echo "Opening required ports..."
echo " - Opening SSH (port 22)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null
echo " - Opening HTTP (port 80)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0 > /dev/null
echo " - Opening HTTPS (port 443)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 > /dev/null
echo " - Opening RDP (port 3389)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 3389 --cidr 0.0.0.0/0 > /dev/null
echo " - Opening Code Server (port 8080)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 8080 --cidr 0.0.0.0/0 > /dev/null

# 2. Create and configure SSH key pair
echo "Creating new key pair..."
for i in 1 2 3; do
    if mkdir -p ~/.ssh && aws ec2 create-key-pair --key-name ${SSH_KEY_NAME} \
           --query 'KeyMaterial' --output text > ~/.ssh/${SSH_KEY_NAME} 2>/dev/null; then
        chmod 600 ~/.ssh/${SSH_KEY_NAME}
        echo " - Key pair created successfully"
        break
    else
        if [ $i -eq 3 ]; then
            echo "Failed to create key pair after 3 attempts. Exiting..."
            exit 1
        fi
        echo " - Creation attempt $i failed, waiting ${i}0 seconds..."
        sleep $((i * 10))
    fi
done

# 3. Launch EC2 instance using Amazon Linux 2023 Minimal AMI
echo "Retrieving the latest Amazon Linux 2023 minimal AMI using SSM parameter..."
AMI_ID=$(aws ssm get-parameter --name "/aws/service/ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-x86_64" --query "Parameter.Value" --output text)
echo "Using AMI ID: $AMI_ID"
echo "Creating instance..."
INSTANCE_ID=$(aws ec2 run-instances --image-id "$AMI_ID" --count 1 --instance-type "$INSTANCE_TYPE" \
    --key-name ${SSH_KEY_NAME} --security-group-ids "$SG_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${INSTANCE_TAG_NAME}}]" \
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
echo "Allocating a new Elastic IP..."
ALLOCATION_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
echo "Tagging Elastic IP..."
aws ec2 create-tags --resources "$ALLOCATION_ID" --tags Key=Name,Value=${ELASTIC_IP_TAG_NAME}
echo "Getting Elastic IP address..."
ELASTIC_IP=$(aws ec2 describe-addresses --allocation-ids "$ALLOCATION_ID" --query 'Addresses[0].PublicIp' --output text)
echo "Associating Elastic IP with the new instance..."
aws ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOCATION_ID" > /dev/null
echo "Host vm configuration added to ~/.ssh/config:"
echo "Host vm
    HostName $ELASTIC_IP
    User ec2-user
    IdentityFile ~/.ssh/${SSH_KEY_NAME}" > ~/.ssh/config

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
# Installation Phase
###########################################
echo "Starting software installation..."
ssh -o StrictHostKeyChecking=no -i ~/.ssh/${SSH_KEY_NAME} ec2-user@$ELASTIC_IP 'set -e

#----------------
# LAMP Stack
#----------------
if [ '"$INSTALL_LAMP"' = true ]; then
    echo "Updating DNF repositories..."
    sudo dnf clean all
    sudo dnf makecache

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
    # Insert VS Code Server installation commands here
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
    sudo mkdir -p /usr/share/httpd/.wp-cli/cache
    sudo chown -R apache:apache /usr/share/httpd/.wp-cli
    echo "Downloading WordPress..."
    sudo -u apache wp core download --path=/var/www/html/

    echo "Installing required PHP modules for WordPress..."
    sudo dnf install -y php php-mysqlnd php-gd php-curl php-dom php-mbstring php-zip php-intl

    echo "Configuring WordPress..."
    sudo mysql -Bse "CREATE USER IF NOT EXISTS wordpressuser@localhost IDENTIFIED BY '\''password'\'';GRANT ALL PRIVILEGES ON *.* TO wordpressuser@localhost;FLUSH PRIVILEGES;"
    sudo -u apache wp config create --dbname=wordpress --dbuser=wordpressuser --dbpass=password --path=/var/www/html/
    wp db create --path=/var/www/html/
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
