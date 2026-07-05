FROM golang:1.26-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/autostream-observability ./cmd/observability

FROM gcr.io/distroless/base-debian13
COPY --from=build /out/autostream-observability /usr/local/bin/autostream-observability
COPY --from=build /out/autostream-observability /usr/local/bin/observability
ENV AUTOSTREAM_NODE_CONFIG=/etc/autostream-node/config.yml
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/autostream-observability"]
