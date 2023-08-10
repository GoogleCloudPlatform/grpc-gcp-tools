#!/bin/bash

# Fail on any error.
set -eo pipefail

# Start interop_server
./interop_server --port 12000 &

# Wait for some time and start client
sleep 2
./client_static --server_host=localhost --test_case=rpc_soak --server_port=12000 --soak_iterations=90 --soak_max_failures=100 --soak_per_iteration_max_acceptable_latency_ms=1000 --soak_min_time_ms_between_rpcs=1000 --soak_overall_timeout_seconds=1800 &

#Wait for some time
sleep 5
# Sending EOF to lightfoot after 2 mins. Timeout just makes sure that the shell does not run forever
(timeout 4m sh -c 'sleep 3m; echo -n ""') | sudo ./lightfoot_static --file_log $(pgrep -f client_static)

if [[ ! $? -eq 0 ]]; then
    echo "lightfoot exited with error."
fi

file="metrics/ebpf.txt"
log_file="logs/ebpf.txt"

# Check if the file exists
if [ ! -f "$file" ]; then
  echo "Error: File $file not found."
  exit 1
fi

# Function to check if a timestamp is at least one minute in the past
function is_timestamp_one_minute_past() {
  current_timestamp=$(date +%s)
  given_timestamp=$(date -d "$1" +%s)
  # Check if the given timestamp is at least one minute in the past
  if [ "$((current_timestamp - given_timestamp))" -ge 60 ]; then
    return 0
  else
    return 1
  fi
}

# Initialize variables to track conditions
h2_stream_count_found=0
tcp_rtt_found=0
last_timestamp=""

# Read data from the file line by line
while IFS= read -r line; do
  # Extract the timestamp from the line
  timestamp=$(echo "$line" | awk -F',' '{print $3}')

  # Check if the h2_stream_count condition is met
  if echo "$line" | grep -q 'h2_stream_count' && [ "$(echo "$line" | awk -F',' '{print $4}' | awk -F':' '{print $2}' )" -gt 30 ]; then
    h2_stream_count_found=1
  fi

  # Check if the tcp_rtt condition is met
  if echo "$line" | grep -q 'tcp_rtt' && [ "$(echo "$line" | awk -F',' '{print $4}' | awk -F':' '{print $2}' |  awk '{ gsub(/[^0-9]/, ""); print }')" -ne 0 ]; then
    tcp_rtt_found=1
  fi

  # Update the last_timestamp with the latest timestamp from the file
  last_timestamp="$timestamp"
done <"$file"

# Check if all conditions are met
if [ "$h2_stream_count_found" -ne 1 ]; then
  echo Stream count not found
  exit 1
fi

if [ "$tcp_rtt_found" -ne 1 ]; then 
  echo Tcp RTT not found
  exit 1
fi


if [ ! -s "$log_file" ]; then
  echo Log file found
  exit 1
fi


if is_timestamp_one_minute_past "$last_timestamp"; then
  echo "Conditions met!"
  exit 0
else
  echo "Conditions not met."
  exit 1
fi

capture_test_logs() {
  # based on http://cs/google3/third_party/fhir/kokoro/common.sh?rcl=211854506&l=18
  mkdir -p "$KOKORO_ARTIFACTS_DIR"
  mkdir -p "$KOKORO_ARTIFACTS_DIR"/tests
  touch "$KOKORO_ARTIFACTS_DIR"/tests/sponge_log.xml
  cat logs/ebpf.txt >> "$KOKORO_ARTIFACTS_DIR"/tests/sponge_log.log
  cat metrics/ebpf.txt >> "$KOKORO_ARTIFACTS_DIR"/tests/sponge_log.log
}

# Run capture_test_logs when the script exits
trap capture_test_logs EXIT
