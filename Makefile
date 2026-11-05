.PHONY: build test-go check-web test-web test-integration clean

build:
	cd web && npm ci && npm run build
	rm -rf cmd/forge/dist
	cp -R web/dist cmd/forge/dist
	mkdir -p bin
	go build -o bin/forge ./cmd/forge

test-go:
	go test ./...

check-web:
	cd web && npm run check

test-web:
	cd web && npm run test

test-integration:
	go test ./...

clean:
	rm -rf bin web/dist
