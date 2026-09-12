# Build a static binary so the runtime image needs no Go toolchain and no libc.
FROM golang:1.26-alpine AS build
WORKDIR /build
COPY go.mod go.sum ./
# Warm the module cache before the sources are copied, so a code change does not
# invalidate the download layer.
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-cipher ./cmd

# Nothing but the binary. A shell in this image would be a shell next to the keys.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-cipher /mcp-cipher
EXPOSE 9090
USER nonroot:nonroot
ENTRYPOINT ["/mcp-cipher"]
