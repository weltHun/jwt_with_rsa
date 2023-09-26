FROM golang:1.21.1 as builder

COPY . /go/source/
WORKDIR /go/source

RUN CGO_ENABLED=0 go build .

FROM alpine:3.14

RUN addgroup -S golang && adduser -S golang -G golang
RUN mkdir -p /usr/src/golang-app && chown -R golang:golang /usr/src/golang-app
USER golang

WORKDIR /usr/src/golang-app
COPY --chown=golang:golang --from=builder /go/source/jwt .

EXPOSE 8080

CMD ["./jwt"]
