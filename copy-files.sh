#!/bin/bash

# Enter the remote server's address and the path to the files you want to copy
REMOTE_SERVER="n6saha@nuc1"
REMOTE_PATH="/home/n6saha/testbed/5g-dockerfiles/"

# Enter the path on your local machine where you want to copy the files
LOCAL_PATH="."

# Enter the path to the filter file you want to use
FILTER_FILE="filter-file.txt"

# Run the rsync command
rsync -avh --filter="merge $FILTER_FILE" "$REMOTE_SERVER:$REMOTE_PATH" "$LOCAL_PATH"

