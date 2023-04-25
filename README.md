# fastcommp

Filecoin fast piece commitment summation tool.

# build

`make build`

# execute

`./testcommp <carfile.car>`

## optional: create car dummy data

1. create an 8 GiB test file

`
dd if=/dev/urandom of=8G-payload.bin bs=1M count=8192
`

2. car it up with `https://github.com/ipld/go-car` (install with `go install github.com/ipld/go-car/cmd/car@latest`)

`
car c --version 1 -f 8G-payload.bin.car 8G-payload.bin
`
