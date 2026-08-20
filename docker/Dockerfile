# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.20

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/web-admin \
    ./

FROM alpine:${ALPINE_VERSION} AS runtime

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=build /out/web-admin /app/web-admin

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/web-admin"]
