#!/bin/bash
set -euo pipefail

###########################################
# AWS CLI v2 Installer
#
# Installs the AWS CLI v2 on Linux (x86_64),
# sets default region/output, and prompts
# the user to enter their AWS credentials.
###########################################

handle_error() {
    echo "Error: $1"
    exit 1
}

install_aws_cli() {
    local download_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
    local installer_file="awscliv2.zip"

    echo "Downloading the AWS CLI installer from: $download_url"
    curl -sS "$download_url" -o "$installer_file" || handle_error "Failed to download the installer."

    echo "Installing the AWS CLI..."
    unzip -qo "$installer_file" || handle_error "Failed to unzip the installer."
    sudo ./aws/install || handle_error "Failed to install the AWS CLI."

    # Clean up installer files
    rm -f "$installer_file"
    rm -rf aws
}

# Install AWS CLI
install_aws_cli

# Verify the installation
echo "Verifying AWS CLI installation..."
aws --version || handle_error "AWS CLI installation verification failed."
echo "AWS CLI installation successful!"

# Set default region and output format
echo "Configuring the AWS CLI..."
aws configure set region eu-west-1
aws configure set output json

# Prompt user for credentials (Access Key ID, Secret Access Key)
aws configure || handle_error "Failed to configure the AWS CLI."
