#!/bin/bash

# Ensure the script is run with a service name argument
if [ -z "$1" ]; then
    echo "Usage: $0 <service_name>"
    exit 1
fi

SERVICE=$1

# Check if the service is installed
if ! systemctl list-unit-files | grep -q "^$SERVICE.service"; then
    echo "not installed"
    exit 0
fi

# Check if the service is active
if systemctl is-active --quiet $SERVICE; then
    echo "active"
else
    echo "not active"
fi
