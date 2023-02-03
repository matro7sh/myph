FROM golang:1.19-alpine as builder

WORKDIR /root
RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache \
    make \
    build-base

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o myph main.go

FROM alpine:3.16.2

WORKDIR /app

COPY --from=builder /root/myph .

ENTRYPOINT [ "/app/myph" ]
