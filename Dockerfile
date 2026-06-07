# Build stage
FROM golang:1.26.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 corona && \
    adduser -D -u 1000 -G corona corona

# Copy binary from builder
COPY --from=builder /app/bin/corona /usr/local/bin/corona

# Switch to non-root user
USER corona

# Set entrypoint
ENTRYPOINT ["corona"]

# Default command (local simulation)
CMD ["l", "0", "0"]