FROM golang:1.23.4-alpine AS golang-builder

# set the working directory
WORKDIR /app

RUN apk add --no-cache curl git

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.58.1

COPY . .

# build the scanner
RUN CGO_ENABLED=0 go build -o devguard-operator main.go

FROM scratch

COPY --from=golang-builder /app/devguard-operator /usr/local/bin/devguard-operator
COPY --from=golang-builder /usr/local/bin/trivy /usr/local/bin/trivy

CMD ["/usr/local/bin/devguard-operator"]