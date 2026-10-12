# Build environment for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The scanner builds this with the repository root as the build context. Network access is
# available only while this image builds; everything the scanning agent needs must be fetched here.
FROM golang:1.26-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git jq procps \
    && rm -rf /var/lib/apt/lists/*

# Scanner contract: the checkout lives inside the image at /src.
COPY . /src
WORKDIR /src

# Fetch every module and compile every package, test and example (including the
# build-tagged integration example) so that offline builds and `go test` work.
RUN go mod download \
    && go build ./... \
    && go test -tags=integration -count=1 -run '^$' ./... >/dev/null

# Baseline unit tests. A failure is reported but does not fail the build.
RUN go test -count=1 ./... || echo "WARNING: openpubkey unit tests reported failures"

# Reproducers and patches must build with the network disabled.
ENV GOPROXY=off \
    GOSUMDB=off

CMD ["bash"]
