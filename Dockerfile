FROM golang:1.23.1-alpine AS golang-builder

# set the working directory
WORKDIR /app

COPY . .

# build the scanner
RUN CGO_ENABLED=0 go build -o devguard-operator main.go

FROM scratch

COPY --from=golang-builder /app/devguard-operator /usr/local/bin/devguard-operator

CMD ["/usr/local/bin/devguard-operator"]