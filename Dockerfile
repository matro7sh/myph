FROM golang:1.20-alpine as builder

WORKDIR /root
RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache \
    make \
    build-base

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o myph .


FROM alpine:3.18.2
LABEL maintainer="djnn <email@djnn.sh>"

RUN adduser -D djnn
USER djnn
WORKDIR /home/djnn

COPY --from=builder /root/myph .

ENTRYPOINT [ "/home/djnn/myph" ]
