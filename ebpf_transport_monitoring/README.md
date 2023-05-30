## Lightfoot

This utility is a monitoring solution which uses eBPF to get HTTP2 metrics from gRPC library from userspace and TCP metrics from kernel space to give you a complete picture of your application.

Currently metrics are reported once per minute.


## Pre-requisites 



1. Kernel version 4.14 and above
2. Currently the utility supports only gRPC golang. 
3. Golang versions 1.17 and above are supported.
4. You need to use sudo to run this application.


## Command line options

To use Lightfoot, you need to provide a list of process IDs (pids) that you want to trace. This can be done by passing the pids as command-line arguments. You can specify multiple pids by separating them with a space.

The following options are available for Lightfoot:



* -f, --file: This option enables logging to a file instead of the standard output.
* -s, --host_level: This option aggregates the events at the host level instead of at the process level.
* -g, --gcp: This option is deprecated and should be replaced with -o. It enables exporting to Stackdriver.
* -o, --oc_gcp: This option enables exporting to Opencensus Stackdriver.
* -l, --custom_labels: This option allows you to attach custom labels to Open Census metrics. The labels should be specified in the format "key:value" and can be provided multiple times.
* -c, --gcp_json_creds: This option allows you to specify the file path to the service account credentials for exporting to GCP.
* -p, --gcp_Project: This option allows you to specify the GCP project ID for exporting data.

Example usage


### Stdout exporter
    sudo ./lightfoot [pids of programs to monitor]

### File exporter
    sudo ./lightfoot [pids of programs to monitor] -f

### GCP exporter
    sudo ./lightfoot [pids of programs to monitor] -g -p <project-id>


The following example uses default google cloud credentials in the environment

In this specific example, please keep in mind that the environment changes on using sudo so to use the Default credentials export the GOOGLE_APPLICATION_CREDENTIALS for the superuser environment as well.

## Build Instructions
1. Clone repository 
2. Install bazel from [https://bazel.build/install](https://bazel.build/install)
3. Install dependencies
    1. m4
    2. clang-11
    3. libssl-dev
    4. libcurl4-openssl-dev 
    5. libarchive-dev
    6. libsqlite3-dev
    7. libmicrohttpd-dev
    8. pkg-config

4. Make sure the paths for clang, llc, and llvm-split.

On installation my machine has clang-11. I used the following to change it to clang. 

    sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 380
    sudo update-alternatives --install /usr/bin/llc llc /usr/bin/llc-11 380
    sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-11 380

5. Build

First compile the eBPF loader

    cd ebpf-h2-golang-prober
    bazel build :lightfoot

6. Building BPF code

In most modern kernels you must use the following instructions to compile bpf code.

    bazel build //sources/bpf_sources:h2_bpf_core
    bazel build //sources/bpf_sources:tcp_bpf_core

7. For older kernels

Build the non core version

    bazel build //sources/bpf_sources:h2_bpf
    bazel build //sources/bpf_sources:tcp_bpf_kprobe

## Information collected


### Metrics


<table>
  <tr>
   <td>Metric
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td>H2 reset stream count
   </td>
   <td>The number of times a HTTP/2 stream has been reset.
   </td>
  </tr>
  <tr>
   <td>H2 stream count
   </td>
   <td>The number of HTTP/2 streams that have been created.
   </td>
  </tr>
  <tr>
   <td>TCP receive bytes
   </td>
   <td>The number of bytes that have been received by the connection.
   </td>
  </tr>
  <tr>
   <td>TCP receive congestion window
   </td>
   <td>The size of the TCP receive congestion window.
   </td>
  </tr>
  <tr>
   <td>TCP retransmits
   </td>
   <td>The number of times a TCP packet has been retransmitted.
   </td>
  </tr>
  <tr>
   <td>TCP round-trip time
   </td>
   <td>The average time it takes for a round trip at tcp level
   </td>
  </tr>
  <tr>
   <td>TCP send bytes
   </td>
   <td>The number of bytes that have been sent by the connection.
   </td>
  </tr>
  <tr>
   <td>TCP send congestion window
   </td>
   <td>The size of the TCP send congestion window.
   </td>
  </tr>
</table>



### Logs 


<table>
  <tr>
   <td>Log 
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td>HTTP2 Go Away
   </td>
   <td>Go away received with error code
   </td>
  </tr>
  <tr>
   <td>HTTP Connection Close
   </td>
   <td>Connection closed 
   </td>
  </tr>
  <tr>
   <td>TCP connection state changes
   </td>
   <td>States are defined in tcp_states.h
   </td>
  </tr>
  <tr>
   <td>HTTP New connection 
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>TCP New connection
   </td>
   <td>
   </td>
  </tr>
</table>
