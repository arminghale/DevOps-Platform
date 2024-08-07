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
echo "Updating package information..."
apt-get update -y

# Check if SQL Server is already installed
if command_exists sqlcmd; then
    sqlcmd -? | grep 'sqlcmd'
    echo "ok"
    exit 0
fi

# Import the public repository GPG keys
echo "Importing the public repository GPG keys..."
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

# Register the Microsoft SQL Server Ubuntu repository
echo "Adding Microsoft SQL Server Ubuntu repository..."
add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/mssql-server-2019.list)"

# Update package information again
echo "Updating package information again..."
apt-get update -y

# Install SQL Server
echo "Installing SQL Server..."
apt-get install -y mssql-server

# Run the SQL Server setup
echo "Running the SQL Server setup..."
/opt/mssql/bin/mssql-conf setup

# Start and enable SQL Server service
echo "Starting SQL Server service..."
systemctl start mssql-server
systemctl enable mssql-server

# Install SQL Server command-line tools
echo "Installing SQL Server command-line tools..."
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list | tee /etc/apt/sources.list.d/msprod.list
apt-get update -y
apt-get install -y mssql-tools unixodbc-dev

# Add SQL Server tools to the PATH
echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc
source ~/.bashrc

# Print SQL Server version
echo "SQL Server installed successfully!"
/opt/mssql/bin/sqlservr --version

# Basic security setup: create admin user
echo "Setting up SQL Server admin user..."
/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P 'fart1234' -Q "CREATE LOGIN [admin] WITH PASSWORD = 'fart1234'; ALTER SERVER ROLE sysadmin ADD MEMBER [admin];"

echo "ok"
