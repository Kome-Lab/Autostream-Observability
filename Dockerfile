FROM golang:1.26-trixie AS build
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/autostream-observability -ldflags="-s -w -X github.com/example/autostream-observability/internal/version.Version=${VERSION} -X github.com/example/autostream-observability/internal/version.Commit=${COMMIT} -X github.com/example/autostream-observability/internal/version.BuildDate=${BUILD_DATE}" ./cmd/observability

FROM gcr.io/distroless/base-debian13
COPY --from=build /out/autostream-observability /usr/local/bin/autostream-observability
COPY --from=build /out/autostream-observability /usr/local/bin/observability
ENV AUTOSTREAM_NODE_CONFIG=/etc/autostream-observability/config.yml
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/autostream-observability"]
