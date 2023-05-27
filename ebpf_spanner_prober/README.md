
# Quick start guide

1. Clone repo:
   ```
   git clone https://github.com/GoogleCloudPlatform/grpc-gcp-tools.git
   ```
1. Build image:
   ```
   docker build -f ./ebpf_spanner_prober/Dockerfile -t ebpf-spanner-prober:v0.2.1 .
   ```
1. Run prober:
   ```
   docker run --rm --pid=host --privileged -v <path_to_credentials>.json:/home/app/gcp-creds.json --env GOOGLE_APPLICATION_CREDENTIALS=/home/app/gcp-creds.json ebpf-spanner-prober:v0.2.1 spanner_prober_args="--project=<project-name> --instance=test1 --database=test1 --qps=1 --probe_type=read" lightfoot_args="-o -p <project-name>"
   ```

The prober will try to create the instance, database, and the table if any of them doesn't exist.

The prober will ship metrics to Cloud Monitoring.

Please check spanner_prober [README](https://github.com/GoogleCloudPlatform/grpc-gcp-go/tree/main/spanner_prober) before running.

[Available spanner prober arguments](https://github.com/GoogleCloudPlatform/grpc-gcp-go/tree/main/spanner_prober#arguments)