# Dockerfile compartilhado — todos os binários do projeto usam o mesmo padrão.
# Selecione o componente via build arg: --build-arg TARGET=coletor
ARG TARGET=servidor

# ── Estágio 1: build ─────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

ARG TARGET
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/app ./cmd/${TARGET}

# ── Estágio 2: runtime mínimo ─────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

ARG TARGET
LABEL component=${TARGET}

COPY --from=builder /bin/app /app

ENTRYPOINT ["/app"]
