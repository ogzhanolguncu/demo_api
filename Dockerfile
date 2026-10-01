FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum* ./
RUN go mod download

RUN echo "KEBAP run www222323231241241242132222e2q2eq2e2qe2qeqwqwqwe2e222" && echo "KEBAP stdout 1" && echo "KEBAP stderr 1" >&2 && echo "KEBAP stdout 2" && echo "KEBAP stderr 2" >&2
RUN for i in $(seq 1 3000); do echo "KEBAP line $i"; [ $((i % 300)) -eq 0 ] && echo "KEBAP err $i" >&2; done; true
RUN for i in $(seq 1 20); do echo "KEBAP slow $i"; echo "KEBAP slow err $i" >&2; sleep 3; done

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
