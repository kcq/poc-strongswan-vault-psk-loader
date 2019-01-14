# Docker image for building the Go app
FROM golang:latest

WORKDIR /go/src/sspoc
COPY . /go/src/sspoc

RUN go get ./...
RUN go build -o app
CMD ["/go/src/sspoc/app"]
