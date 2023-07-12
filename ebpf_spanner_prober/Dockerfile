# Build lightfoot
FROM debian:bullseye

RUN apt update && apt upgrade -y && apt install -y apt-transport-https curl gnupg
RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel-archive-keyring.gpg
RUN mv bazel-archive-keyring.gpg /usr/share/keyrings
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt update && apt install -y m4 clang-11 libssl-dev libcurl4-openssl-dev libarchive-dev libsqlite3-dev libmicrohttpd-dev pkg-config git bazel

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 380 && \
    update-alternatives --install /usr/bin/llc llc /usr/bin/llc-11 380 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-11 380

WORKDIR /app/build/ebpf_transport_monitoring

COPY ebpf_transport_monitoring /app/build/ebpf_transport_monitoring

RUN bazel build :lightfoot

# Build spanner_prober
FROM golang:1.19

RUN git clone https://github.com/GoogleCloudPlatform/grpc-gcp-go.git /go/src/github.com/GoogleCloudPlatform/grpc-gcp-go
WORKDIR /go/src/github.com/GoogleCloudPlatform/grpc-gcp-go/spanner_prober
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -v -o /go/src/github.com/GoogleCloudPlatform/grpc-gcp-go/spanner_prober ./...

# Create image with lightfoot & spanner_prober
FROM debian:bullseye

RUN apt update && apt upgrade -y && apt -y install curl libc6 elfutils

WORKDIR /home/app
COPY --from=0 /app/build/ebpf_transport_monitoring/bazel-out/k8-fastbuild/bin/lightfoot ./
COPY --from=1 /go/src/github.com/GoogleCloudPlatform/grpc-gcp-go/spanner_prober/spanner_prober ./

COPY ebpf_spanner_prober/run.sh /home/app

ENTRYPOINT [ "bash", "run.sh" ]
