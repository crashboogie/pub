#!/bin/bash

# Simple bash script to monitor running processes on a host

# Loop by Line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "old_process") <(echo "$new_process")
	sleep 1
	old_process=$new_process
done
