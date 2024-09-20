FROM golang AS builder

WORKDIR /go/src/PR-DNSd

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux \
  go build -a -installsuffix cgo -o /go/bin/ \
  -ldflags "-X main.DefaultChroot=" \
  ./...

FROM scratch

COPY --from=builder /go/bin/* /bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/ca-bundle.pem

EXPOSE 53/udp

ENTRYPOINT [ "/bin/PR-DNSd" ]
