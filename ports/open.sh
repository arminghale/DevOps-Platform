#!/bin/bash

# Function to check if the port number is valid
is_valid_port() {
    if [[ $1 -lt 1 || $1 -gt 65535 ]]; then
        echo "Invalid port number. Please provide a port number between 1 and 65535."
        exit 1
    fi
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if a port number is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <port_number>"
    exit 1
fi

# Validate the port number
PORT=$1
is_valid_port $PORT

# Open the specified port using iptables
echo "Opening port $PORT..."
iptables -A INPUT -p tcp --dport $PORT -j ACCEPT
iptables -A INPUT -p udp --dport $PORT -j ACCEPT

# Save the iptables rules to ensure they persist after reboot
if command -v iptables-save &> /dev/null; then
    echo "Saving iptables rules..."
    iptables-save > /etc/iptables/rules.v4
else
    echo "iptables-save command not found. iptables rules will not persist after reboot."
fi

echo "ok"

