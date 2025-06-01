.PHONY: build test fmt lint

build:
	go build -o node ./cmd/node

test:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run
