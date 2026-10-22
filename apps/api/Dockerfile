# syntax=docker/dockerfile:1
# The build stage runs on the builder's own platform and cross-compiles (pure
# Go, CGO off), so multi-arch release builds do not run the compiler under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG VERSION=dev
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X nazr/api/internal/version.Version=${VERSION}" -o /out/nazr ./cmd/nazr
RUN mkdir -p /data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/nazr /nazr
# Created nonroot-owned so a fresh named volume mounted here inherits it.
COPY --from=build --chown=65532:65532 /data /data
VOLUME /data
EXPOSE 443 80 9090
USER nonroot
ENTRYPOINT ["/nazr"]
CMD ["serve"]
