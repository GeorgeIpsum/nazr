# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
ARG VERSION=dev
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w -X nazr/api/internal/version.Version=${VERSION}" -o /out/nazr ./cmd/nazr

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/nazr /nazr
VOLUME /data
EXPOSE 443 80 9090
USER nonroot
ENTRYPOINT ["/nazr"]
CMD ["serve"]
