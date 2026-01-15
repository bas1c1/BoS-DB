FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .

RUN go mod init bos-db && \
    go mod tidy

RUN CGO_ENABLED=0 GO111MODULE=on go build -ldflags="-w -s -extldflags=-static" -o bos_db

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/bos_db /
USER nonroot:nonroot
CMD ["/bos_db", "-port", "6379"]