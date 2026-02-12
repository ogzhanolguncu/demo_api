FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Enable CGO for SQLite support
RUN CGO_ENABLED=1 GOOS=linux go build -a -o main .

FROM alpine:latest

# Install SQLite runtime and ca-certificates
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /root/

COPY --from=builder /app/main .

ENV PORT 3131

CMD ["./main"]
