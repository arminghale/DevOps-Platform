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

# Check if MongoDB is already installed
if command_exists mongod; then
    mongod --version
    echo "ok"
    exit 0
fi

# Install necessary packages
sudo apt-get install -y wget gnupg

# Add MongoDB repository
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

# Update package information again
sudo apt-get update

# Install MongoDB
sudo apt-get install -y mongodb-org

# Start MongoDB service
sudo systemctl start mongod
sudo systemctl enable mongod

# Verify installation
mongod --version

# Basic security setup: create admin user
echo "Setting up MongoDB admin user..."
mongo <<EOF
use admin
db.createUser({
  user: "admin",
  pwd: "fart1234",
  roles: [{ role: "userAdminAnyDatabase", db: "admin" }]
})
EOF

# Enable authentication in MongoDB configuration
echo "Enabling authentication in MongoDB configuration..."
sed -i '/#security:/a\  authorization: "enabled"' /etc/mongod.conf

# Restart MongoDB service to apply changes
echo "Restarting MongoDB service..."
systemctl restart mongod

echo "ok"
