FROM ghcr.io/cybozu/golang:1.24-noble AS builder

WORKDIR /work

COPY . /work

RUN apt update && \
    apt install -y clang llvm make

# make sure the bpf program is built on the host
RUN go build -o msq-obsrv .

FROM ghcr.io/cybozu/ubuntu:24.04

COPY --from=builder /work/msq-obsrv /usr/local/bin/msq-obsrv

ENTRYPOINT ["/usr/local/bin/msq-obsrv"]
