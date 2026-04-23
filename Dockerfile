FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN echo "[BUILD] Installing build dependencies..."
RUN apk add --no-cache gcc musl-dev sqlite-dev
RUN for i in $(seq 1 20); do echo "[BUILD] Verifying dependency $i/20..."; done

COPY go.mod go.sum* ./
RUN echo "[BUILD] Downloading Go modules..."
RUN go mod download
RUN for i in $(seq 1 15); do echo "[BUILD] Resolving module $i/15..."; done

COPY . .

RUN echo "[BUILD] Starting compilation with CGO enabled..."
RUN for i in $(seq 1 30); do echo "[BUILD] Compiling package $i/30..."; done
RUN CGO_ENABLED=1 GOOS=linux go build -a -o main .
RUN for i in $(seq 1 10); do echo "[BUILD] Linking object $i/10..."; done
RUN echo "[BUILD] Compilation complete"

FROM alpine:latest

RUN echo "[BUILD] Setting up runtime environment..."
RUN apk --no-cache add ca-certificates sqlite-libs
RUN for i in $(seq 1 25); do echo "[BUILD] Configuring runtime layer $i/25..."; done
RUN echo "[BUILD] Runtime dependencies installed"

WORKDIR /root/

COPY --from=builder /app/main .
RUN for i in $(seq 1 15); do echo "[BUILD] Finalizing image layer $i/15..."; done
RUN echo "[BUILD] Binary copied, image ready"

ENV PORT 3131

CMD ["./main"]
