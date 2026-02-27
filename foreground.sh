#!/bin/bash
# Move to the scenario directory
cd /root/web-challenge

# Build the Docker image (takes ~30-60 seconds)
echo "Setting up your private sandbox... please wait."
docker build -t ctf-app .

# Run the container and map internal port 5000 to external port 80
docker run -d -p 80:5000 --name web-sandbox ctf-app

echo "------------------------------------------------"
echo "Sandbox is READY!"
echo "Click the 'Web Access' tab to start hacking."
echo "------------------------------------------------"