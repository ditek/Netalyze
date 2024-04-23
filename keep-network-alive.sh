#!/bin/bash

# Check if we have internet. If not, restart the executable.
# Usage: ./keep-network-alive.sh /path/to/executable
# It's recommended to schedule this in a root cron job:
# sudo crontab -e

# Path to the executable
EXECUTABLE=$1

# Function to check internet connectivity
check_internet() {
    ping -c 1 8.8.8.8 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Internet is up."
        return 0
    else
        echo "Internet is down."
        return 1
    fi
}

# Function to get the process ID of the executable
get_pid() {
    pgrep -f $EXECUTABLE
}

# Start the executable
start_executable() {
    if [ -z "$(get_pid)" ]; then
        echo "Starting the executable as it's not running."
        $EXECUTABLE &
    else
        echo "Executable is already running."
    fi
}

# Stop the executable
kill_executable() {
    PID=$(get_pid)
    if [ ! -z "$PID" ]; then
        echo "Killing the executable."
        kill $PID
    else
        echo "Executable is not running."
    fi
}

# Check the internet and manage the executable accordingly
if check_internet; then
    echo "Internet check passed."
    start_executable
else
    echo "Internet check failed. Restarting the executable."
    kill_executable
    sleep 5
    start_executable
fi
