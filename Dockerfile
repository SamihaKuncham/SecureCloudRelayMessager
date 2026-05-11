FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o relay ./relay

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/relay .
COPY security/keys/ security/keys/
EXPOSE 9000
CMD ["./relay"]
