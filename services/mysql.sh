#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Update package information
sudo apt-get update

# Check if MySQL is already installed
if command_exists mysql; then
    mysql --version
    echo "ok"
    exit 0
fi

# Set MySQL root password
MYSQL_ROOT_PASSWORD="fart1234"

# Preconfigure MySQL installation
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD"

# Install MySQL server
sudo apt-get install -y mysql-server

# Secure MySQL installation
sudo mysql_secure_installation <<EOF

y
$MYSQL_ROOT_PASSWORD
$MYSQL_ROOT_PASSWORD
y
y
y
y
EOF

# Enable and start MySQL service
sudo systemctl enable mysql
sudo systemctl start mysql

# Print MySQL version to verify installation
mysql --version

echo "ok"
