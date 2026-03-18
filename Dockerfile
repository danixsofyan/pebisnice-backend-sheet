# ── Stage 1: Build ────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install dependencies untuk build (git diperlukan go mod download)
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go.mod dan go.sum dulu (layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary — static binary untuk Alpine
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o pebisnice-backend .

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

# Copy binary dari builder
COPY --from=builder /app/pebisnice-backend .

# Port yang dipakai (Leapcell inject PORT via env)
EXPOSE 8080

# Run
CMD ["./pebisnice-backend"]
