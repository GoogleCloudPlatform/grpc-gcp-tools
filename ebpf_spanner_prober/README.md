
# eBPF spanner prober

This is [Cloud Spanner prober](https://github.com/GoogleCloudPlatform/grpc-gcp-go/tree/main/spanner_prober) bundled with [eBPF prober](https://github.com/GoogleCloudPlatform/grpc-gcp-tools/blob/master/ebpf_transport_monitoring). See projects pages for metrics provided by the probes.

## Quick start guide

This guide assumes that Cloud Spanner and Cloud Monitoring/Logging APIs are enabled in GCP and credentials with necessary permissions are available.

You can grant Spanner Admin role to the prober to create instance, database, table. Or you can create an instance and a database manually (or use existing ones) and grant only read/write and create table permissions to the prober.

1. Clone repo:
   ```
   git clone https://github.com/GoogleCloudPlatform/grpc-gcp-tools.git
   cd grpc-gcp-tools
   ```
1. Build image:
   ```
   docker build -f ./ebpf_spanner_prober/Dockerfile -t ebpf-spanner-prober:v0.3.1 .
   ```
1. Run prober:
   ```
   docker run --rm --pid=host --privileged -v <path_to_credentials>.json:/home/app/gcp-creds.json --env GOOGLE_APPLICATION_CREDENTIALS=/home/app/gcp-creds.json ebpf-spanner-prober:v0.3.1 spanner_prober_args="--project=<project-name> --instance=test1 --database=test1 --qps=1 --probe_type=strong_query" lightfoot_args="-o -p <project-name>"
   ```

The prober will try to create the instance, database, and the table if any of them doesn't exist.

The prober will ship metrics to Cloud Monitoring and logs to Cloud Logging.

Please check spanner_prober [README](https://github.com/GoogleCloudPlatform/grpc-gcp-go/tree/main/spanner_prober) and eBPF prober (lightfoot) [README](https://github.com/GoogleCloudPlatform/grpc-gcp-tools/blob/master/ebpf_transport_monitoring) before running.

To check whether the eBPF prober can run properly run `ebpf_transport_monitoring/check_environment.sh` on the host (not in the container). The output should look like:

```
Kernel compiled with eBPF support
Kernel compiled with vmlinux support
You can use ebpf-transport-monitoring binary
```

## References

[Spanner prober command line options](https://github.com/GoogleCloudPlatform/grpc-gcp-go/tree/main/spanner_prober#arguments)

[eBPF prober command line options](https://github.com/GoogleCloudPlatform/grpc-gcp-tools/tree/master/ebpf_transport_monitoring#command-line-options)
