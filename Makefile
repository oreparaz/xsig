all: build-all

build-all:
	mkdir -p build
	go build -o build/demo cmd/demo/demo.go
	cd build && ./demo
