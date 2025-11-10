FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o sushi-ssh .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sushi-ssh .
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/sushi-ssh /app/sushi-ssh

ENTRYPOINT ["/app/sushi-ssh"]
#ENTRYPOINT ["tail", "-f", "/dev/null"]
