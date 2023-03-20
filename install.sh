#!/bin/bash

# Update the package list and install necessary packages
apt update
apt install -y python3 python3-pip nmap sqlite3 git

# Clone the repository
git clone https://github.com/5H13LD-7R4C3/python-scanner.git

# Install Python packages
cd /python-scanner
pip3 install -r requirements.txt
# Run the app in the background
nohup python3 app.py > app.log 2>&1 &

echo "Installation complete! The app is now running in the background."
