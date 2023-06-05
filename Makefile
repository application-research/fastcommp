build:
	go build -o fastcommp cmd/main.go

run:
	go run cmd/main.go

clean:
	rm ./fastcommp 8G-payload.bin

gentest:
	dd if=/dev/urandom of=8G-payload.bin bs=1M count=8192

test:
	./fastcommp 8G-payload.bin
