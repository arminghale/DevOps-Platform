#!/bin/bash

sudo apt update

# install basics
sudo apt install net-tools iproute2 lsof

# if python < 3.11 --> using ubuntu 20.4 which python3.8 is default
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.11
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 2
sudo update-alternatives --set python3 /usr/bin/python3.11
sudo curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo python3 get-pip.py

# install docker
sudo apt update
sudo apt install docker.io

# install nginx
sudo apt install nginx
sudo ufw allow 'Nginx Full'

# install requirements
sudo python3 -m pip install -r requirements.txt

# +x permission to bash script files
find ../services/ -type f -iname "*.sh" -exec chmod +x {} \;
find ../ports/ -type f -iname "*.sh" -exec chmod +x {} \;