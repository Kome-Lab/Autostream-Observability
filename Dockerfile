FROM golang:1.26-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/observability ./cmd/observability

FROM gcr.io/distroless/base-debian13
COPY --from=build /out/observability /usr/local/bin/observability
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/observability"]
