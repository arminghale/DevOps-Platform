﻿#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if netstat or ss and lsof are available
if ! command_exists netstat && ! command_exists ss; then
    echo "Neither netstat nor ss command found. Please install one of them."
    exit 1
fi

if ! command_exists lsof; then
    echo "lsof command not found. Please install it."
    exit 1
fi

# Function to display open ports and services using netstat
show_open_ports_netstat() {
    echo "Open ports and listening services (using netstat):"
    netstat -tuln | grep LISTEN
    echo
    echo "Services listening on open ports (using netstat and lsof):"
    netstat -tuln | grep LISTEN | awk '{print $4}' | sed 's/.*://' | while read port; do
        lsof -i :"$port" | grep LISTEN
    done
}

# Function to display open ports and services using ss
show_open_ports_ss() {
    echo "Open ports and listening services (using ss):"
    ss -tuln | grep LISTEN
    echo
    echo "Services listening on open ports (using ss and lsof):"
    ss -tuln | grep LISTEN | awk '{print $5}' | sed 's/.*://' | while read port; do
        lsof -i :"$port" | grep LISTEN
    done
}

# Display open ports and services
if command_exists netstat; then
    show_open_ports_netstat
else
    show_open_ports_ss
fi
