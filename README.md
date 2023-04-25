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
# benchmarks

<img width="955" alt="Screenshot 2023-04-25 at 4 41 58 PM" src="https://user-images.githubusercontent.com/1556714/234313247-56e573e6-107d-4606-8de6-379a92a613e9.png">
* benchmarks run on optimized AMD hardware with ~1TB available memory
