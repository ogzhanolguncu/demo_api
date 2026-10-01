FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum* ./
RUN go mod download

RUN echo "KEBAP run www222323231241241242132222e2q2eq2e2qe2qeqwqwqwe2e222" && echo "KEBAP stdout 1" && echo "KEBAP stderr 1" >&2 && echo "KEBAP stdout 2" && echo "KEBAP stderr 2" >&2
RUN for i in $(seq 1 3000); do echo "KEBAP line $i"; [ $((i % 300)) -eq 0 ] && echo "KEBAP err $i" >&2; done; true
RUN printf '\033[32mKEBAP green\033[0m \033[1;31mKEBAP bold red\033[0m \033[4mKEBAP underline\033[0m\n' && printf '\033[2K\033[1GKEBAP after erase\n' && printf 'KEBAP crlf line\r\n'
RUN for i in 10 20 30 40 50 60 70 80 90 100; do printf '\rKEBAP fast progress %s%%' $i; done; printf '\n'
RUN for i in 10 20 30 40 50 60 70 80 90 100; do printf '\rKEBAP slow progress %s%%' $i; sleep 0.3; done; printf '\n'

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
