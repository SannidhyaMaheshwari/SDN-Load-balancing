#!/bin/bash

# Start iperf client on h1, binding to source port 5001 
echo "Starting iperf client on h1 (sending from port 5001 to h2 on port 5001 for 10 seconds)..."
iperf -c 10.0.0.2 -p 5001 -B 10.0.0.1:5001 -t 2 &  # Connect to h2 (10.0.0.2) on port 5001, using source port 5001 on h1

# Start iperf client on h1, binding to source port 5002
echo "Starting iperf client on h1 (sending from port 5002 to h2 on port 5001 for 5 seconds)..."
iperf -c 10.0.0.2 -p 5001 -B 10.0.0.1:5002 -t 2 &  # Connect to h2 (10.0.0.2) on port 5001, using source port 5002 on h1

# Start iperf client on h1, binding to source port 5003 
echo "Starting iperf client on h1 (sending from port 5003 to h2 on port 5001 for 15 seconds)..."
iperf -c 10.0.0.2 -p 5001 -B 10.0.0.1:5003 -t 2 &  # Connect to h2 (10.0.0.2) on port 5001, using source port 5003 on h1

# Wait for all tests to finish
wait

echo "All iperf tests complete."

