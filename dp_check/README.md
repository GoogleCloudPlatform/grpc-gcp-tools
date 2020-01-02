# dp_check

dp_check is a command line tool for checking the proper configuration and setup
of a VM (the one that it's being ran on) with respect to DirectPath and a
particular service.

## To start using dp_check

Download the binary from the
[release page](https://github.com/GoogleCloudPlatform/grpc-gcp-tools/releases)
and scp the file to your DirectPath enabled VM using
[gcloud command](https://cloud.google.com/sdk/gcloud/reference/compute/scp). In
your VM, run the command:

```sh
./dp_check --service=<SERVICE NAME>
```
