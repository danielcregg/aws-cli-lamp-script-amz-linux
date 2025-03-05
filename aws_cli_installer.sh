#!/bin/bash

# Script to install the AWS CLI v2 on Linux

# Function to handle errors
handle_error() {
  echo "Error: $1"
  exit 1
}

# Function to download the package and manage the installation
install_aws_cli() {
    local download_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
    local installer_file="awscliv2.zip"
    local install_command="unzip awscliv2.zip && sudo ./aws/install"

    echo "Downloading the AWS CLI installer from: $download_url"
    curl -s "$download_url" -o "$installer_file" || handle_error "Failed to download the installer."
    echo "Installing the AWS CLI..."
    eval "$install_command" || handle_error "Failed to install the AWS CLI."
}

# Install AWS CLI
install_aws_cli

# Verify the installation
echo "Verifying AWS CLI installation..."
aws --version || handle_error "AWS CLI installation verification failed."

echo "AWS CLI installation successful!"

# Clean up the installer file and the unzipped folder
rm -f awscliv2.zip
rm -rf aws

# Configure the AWS CLI
echo "Configuring the AWS CLI..."
#set region
aws configure set region eu-west-1
#set output format
aws configure set output json
# Ask user to configure the AWS CLI
aws configure || handle_error "Failed to configure the AWS CLI."
