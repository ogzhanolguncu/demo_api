#!/bin/bash

# Build Docker image
echo "Building Docker image..."
docker build -t demo-api:sqlite .

# Run container
echo "Starting container..."
docker run -d -p 8080:8080 \
  -e UNKEY_ROOT_KEY="test_key_123" \
  -e API_KEY="api_key_456" \
  -e DEBUG_MODE="true" \
  --name demo-api-test \
  demo-api:sqlite

# Wait for server to start
sleep 3

# Test the SQLite endpoint
echo -e "\n=== Testing SQLite Database ==="

echo -e "\n1. Creating log entries..."
curl -X POST http://localhost:8080/v1/db-test \
  -H "Content-Type: application/json" \
  -d '{"message":"Docker test log 1"}'

curl -X POST http://localhost:8080/v1/db-test \
  -H "Content-Type: application/json" \
  -d '{"message":"Docker test log 2"}'

echo -e "\n\n2. Retrieving logs..."
curl -s http://localhost:8080/v1/db-test | jq .

echo -e "\n\n3. Testing root endpoint..."
curl -s http://localhost:8080/ | jq .meta

echo -e "\n\n=== Checking logs ==="
docker logs demo-api-test

echo -e "\n\n=== Cleanup ==="
echo "To stop and remove container, run:"
echo "docker stop demo-api-test && docker rm demo-api-test"
