#!/bin/bash

# Update the package list and install necessary packages
apt update
apt install -y python3 python3-pip nmap sqlite3 git

# Clone the repository
git clone https://github.com/your_username/your_repository.git

# Install Python packages
cd your_repository
pip3 install -r requirements.txt

# Create and populate the database
python3 createdb.py
python3 populate_db.py

# Run the app in the background
nohup python3 app.py > app.log 2>&1 &

echo "Installation complete! The app is now running in the background."