#!/bin/bash

# Define variables
REMOTE_HOST="n6saha@nuc1"
REMOTE_DIR="/home/n6saha/testbed/5g-dockerfiles"

# Check if required variables are set
if [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_DIR" ]; then
  echo "One or more required variables are not set."
  echo "To set REMOTE_HOST, run the following command on the remote machine to get the hostname:"
  echo "hostname"
  echo "To set REMOTE_DIR, please set the path to the remote directory."
  exit 1
fi

# Connect to remote server and deploy code
rsync -avz --exclude '.DS_Store' --exclude 'node_modules' --exclude '.git' --exclude '.gitignore' . ${REMOTE_HOST}:${REMOTE_DIR}
