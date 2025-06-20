APP_NAME=mock-oidc
GO_FILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: all build run lint test docker docker-build clean

all: build

build:
	go build -o $(APP_NAME) main.go

run: build
	./$(APP_NAME)

lint:
	golangci-lint run

test:
	go test ./...

docker:
	docker build -t $(APP_NAME):latest .

docker-build: docker
	@echo "Docker image built successfully with templates included"

clean:
	rm -f $(APP_NAME) 