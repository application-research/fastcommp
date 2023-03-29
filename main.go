package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/pborman/options"

	"hash"
	"math/bits"
	"sync"

	//sha256simd "github.com/minio/sha256-simd"
	sha256simd "crypto/sha256"

	"golang.org/x/xerrors"
)

// Calc is an implementation of a commP "hash" calculator, implementing the
// familiar hash.Hash interface. The zero-value of this object is ready to
// accept Write()s without further initialization.
type Calc struct {
	state
	mu sync.Mutex
}
type state struct {
	quadsEnqueued uint64
	layerQueues   [MaxLayers + 2]chan []byte // one extra layer for the initial leaves, one more for the dummy never-to-use channel
	resultCommP   chan []byte
	buffer        []byte
}

var _ hash.Hash = &Calc{} // make sure we are hash.Hash compliant

// MaxLayers is the current maximum height of the rust-fil-proofs proving tree.
const MaxLayers = uint(31) // result of log2( 64 GiB / 32 )

// MaxPieceSize is the current maximum size of the rust-fil-proofs proving tree.
const MaxPieceSize = uint64(1 << (MaxLayers + 5))

// MaxPiecePayload is the maximum amount of data that one can Write() to the
// Calc object, before needing to derive a Digest(). Constrained by the value
// of MaxLayers.
const MaxPiecePayload = MaxPieceSize / 128 * 127

// MinPiecePayload is the smallest amount of data for which FR32 padding has
// a defined result. It is not possible to derive a Digest() before Write()ing
// at least this amount of bytes.
const MinPiecePayload = uint64(65)

const (
	commpDigestSize = sha256simd.Size
	quadPayload     = 127
	bufferSize      = 256 * quadPayload // FIXME: tune better, chosen by rough experiment
)

var (
	layerQueueDepth   = 32 // FIXME: tune better, chosen by rough experiment
	shaPool           = sync.Pool{New: func() interface{} { return sha256simd.New() }}
	stackedNulPadding [MaxLayers][]byte
)

// initialize the nul padding stack (cheap to do upfront, just MaxLayers loops)
func init() {
	h := shaPool.Get().(hash.Hash)

	stackedNulPadding[0] = make([]byte, commpDigestSize)
	for i := uint(1); i < MaxLayers; i++ {
		h.Reset()
		h.Write(stackedNulPadding[i-1]) // yes, got to...
		h.Write(stackedNulPadding[i-1]) // ...do it twice
		stackedNulPadding[i] = h.Sum(make([]byte, 0, commpDigestSize))
		stackedNulPadding[i][31] &= 0x3F
	}

	shaPool.Put(h)
}

// BlockSize is the amount of bytes consumed by the commP algorithm in one go.
// Write()ing data in multiples of BlockSize would obviate the need to maintain
// an internal carry buffer. The BlockSize of this module is 127 bytes.
func (cp *Calc) BlockSize() int { return quadPayload }

// Size is the amount of bytes returned on Sum()/Digest(), which is 32 bytes
// for this module.
func (cp *Calc) Size() int { return commpDigestSize }

// Reset re-initializes the accumulator object, clearing its state and
// terminating all background goroutines. It is safe to Reset() an accumulator
// in any state.
func (cp *Calc) Reset() {
	cp.mu.Lock()
	if cp.buffer != nil {
		// we are resetting without digesting: close everything out to terminate
		// the layer workers
		close(cp.layerQueues[0])
		<-cp.resultCommP
	}
	cp.state = state{} // reset
	cp.mu.Unlock()
}

// Sum is a thin wrapper around Digest() and is provided solely to satisfy
// the hash.Hash interface. It panics on errors returned from Digest().
// Note that unlike classic (hash.Hash).Sum(), calling this method is
// destructive: the internal state is reset and all goroutines kicked off
// by Write() are terminated.
func (cp *Calc) Sum(buf []byte) []byte {
	commP, _, err := cp.Digest()
	if err != nil {
		panic(err)
	}
	return append(buf, commP...)
}

// Digest collapses the internal hash state and returns the resulting raw 32
// bytes of commP and the padded piece size, or alternatively an error in
// case of insufficient accumulated state. On success invokes Reset(), which
// terminates all goroutines kicked off by Write().
func (cp *Calc) Digest() (commP []byte, paddedPieceSize uint64, err error) {
	cp.mu.Lock()

	defer func() {
		// reset only if we did succeed
		if err == nil {
			cp.state = state{}
		}
		cp.mu.Unlock()
	}()

	if processed := cp.quadsEnqueued*quadPayload + uint64(len(cp.buffer)); processed < MinPiecePayload {
		err = xerrors.Errorf(
			"insufficient state accumulated: commP is not defined for inputs shorter than %d bytes, but only %d processed so far",
			MinPiecePayload, processed,
		)
		return
	}

	// If any, flush remaining bytes padded up with zeroes
	if len(cp.buffer) > 0 {
		if mod := len(cp.buffer) % quadPayload; mod != 0 {
			cp.buffer = append(cp.buffer, make([]byte, quadPayload-mod)...)
		}
		for len(cp.buffer) > 0 {
			// FIXME: there is a smarter way to do this instead of 127-at-a-time,
			// but that's for another PR
			cp.digestQuads(cp.buffer[:127])
			cp.buffer = cp.buffer[127:]
		}
	}

	// This is how we signal to the bottom of the stack that we are done
	// which in turn collapses the rest all the way to resultCommP
	close(cp.layerQueues[0])

	paddedPieceSize = cp.quadsEnqueued * 128
	// hacky round-up-to-next-pow2
	if bits.OnesCount64(paddedPieceSize) != 1 {
		paddedPieceSize = 1 << uint(64-bits.LeadingZeros64(paddedPieceSize))
	}

	return <-cp.resultCommP, paddedPieceSize, nil
}

// Write adds bytes to the accumulator, for a subsequent Digest(). Upon the
// first call of this method a few goroutines are started in the background to
// service each layer of the digest tower. If you wrote some data and then
// decide to abandon the object without invoking Digest(), you need to call
// Reset() to terminate all remaining background workers. Unlike a typical
// (hash.Hash).Write, calling this method can return an error when the total
// amount of bytes is about to go over the maximum currently supported by
// Filecoin.
func (cp *Calc) Write(input []byte) (int, error) {
	if len(input) == 0 {
		return 0, nil
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if MaxPiecePayload <
		(cp.quadsEnqueued*quadPayload)+
			uint64(len(input)) {
		return 0, xerrors.Errorf(
			"writing additional %d bytes to the accumulator would overflow the maximum supported unpadded piece size %d",
			len(input), MaxPiecePayload,
		)
	}

	// just starting: initialize internal state, start first background layer-goroutine
	if cp.buffer == nil {
		cp.buffer = make([]byte, 0, bufferSize)
		cp.resultCommP = make(chan []byte, 1)
		cp.layerQueues[0] = make(chan []byte, layerQueueDepth)
		cp.addLayer(0)
	}

	// short Write() - just buffer it
	if len(cp.buffer)+len(input) < bufferSize {
		cp.buffer = append(cp.buffer, input...)
		return len(input), nil
	}

	totalInputBytes := len(input)

	if toSplice := bufferSize - len(cp.buffer); toSplice < bufferSize {
		cp.buffer = append(cp.buffer, input[:toSplice]...)
		input = input[toSplice:]

		cp.digestQuads(cp.buffer)
		cp.buffer = cp.buffer[:0]
	}

	for len(input) >= bufferSize {
		cp.digestQuads(input[:bufferSize])
		input = input[bufferSize:]
	}

	if len(input) > 0 {
		cp.buffer = append(cp.buffer, input...)
	}

	return totalInputBytes, nil
}

// always called with power-of-2 amount of quads
func (cp *Calc) digestQuads(inSlab []byte) {

	quadsCount := len(inSlab) / 127
	cp.quadsEnqueued += uint64(quadsCount)
	outSlab := make([]byte, quadsCount*128)

	for j := 0; j < quadsCount; j++ {
		// Cycle over four(4) 31-byte groups, leaving 1 byte in between:
		// 31 + 1 + 31 + 1 + 31 + 1 + 31 = 127
		input := inSlab[j*127 : (j+1)*127]
		expander := outSlab[j*128 : (j+1)*128]
		inputPlus1, expanderPlus1 := input[1:], expander[1:]

		// First 31 bytes + 6 bits are taken as-is (trimmed later)
		// Note that copying them into the expansion buffer is mandatory:
		// we will be feeding it to the workers which reuse the bottom half
		// of the chunk for the result
		copy(expander[:], input[:32])

		// first 2-bit "shim" forced into the otherwise identical bitstream
		expander[31] &= 0x3F

		//  In: {{ C[7] C[6] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
		// Out:                 X[5] X[4] X[3] X[2] X[1] X[0] C[7] C[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] X[7] X[6] Z[5] Z[4] Z[3]...
		for i := 31; i < 63; i++ {
			expanderPlus1[i] = inputPlus1[i]<<2 | input[i]>>6
		}

		// next 2-bit shim
		expander[63] &= 0x3F

		//  In: {{ C[7] C[6] C[5] C[4] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
		// Out:                           X[3] X[2] X[1] X[0] C[7] C[6] C[5] C[4] Y[3] Y[2] Y[1] Y[0] X[7] X[6] X[5] X[4] Z[3] Z[2] Z[1]...
		for i := 63; i < 95; i++ {
			expanderPlus1[i] = inputPlus1[i]<<4 | input[i]>>4
		}

		// next 2-bit shim
		expander[95] &= 0x3F

		//  In: {{ C[7] C[6] C[5] C[4] C[3] C[2] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
		// Out:                                     X[1] X[0] C[7] C[6] C[5] C[4] C[3] C[2] Y[1] Y[0] X[7] X[6] X[5] X[4] X[3] X[2] Z[1] Z[0] Y[7]...
		for i := 95; i < 126; i++ {
			expanderPlus1[i] = inputPlus1[i]<<6 | input[i]>>2
		}

		// the final 6 bit remainder is exactly the value of the last expanded byte
		expander[127] = input[126] >> 2
	}

	cp.layerQueues[0] <- outSlab
}

func (cp *Calc) addLayer(myIdx uint) {
	// the next layer channel, which we might *not* use
	if cp.layerQueues[myIdx+1] != nil {
		panic("addLayer called more than once with identical idx argument")
	}
	cp.layerQueues[myIdx+1] = make(chan []byte, layerQueueDepth)

	go func() {
		var twinHold []byte

		for {
			slab, queueIsOpen := <-cp.layerQueues[myIdx]

			// the dream is collapsing
			if !queueIsOpen {
				defer func() { twinHold = nil }()

				// I am last
				if myIdx == MaxLayers || cp.layerQueues[myIdx+2] == nil {
					cp.resultCommP <- append(make([]byte, 0, 32), twinHold[0:32]...)
					return
				}

				if twinHold != nil {
					copy(twinHold[32:64], stackedNulPadding[myIdx])
					cp.hashSlab254(0, twinHold[0:64])
					cp.layerQueues[myIdx+1] <- twinHold[0:64:64]
				}

				// signal the next in line that they are done too
				close(cp.layerQueues[myIdx+1])
				return
			}

			var pushedWork bool

			switch {
			case len(slab) > 1<<(5+myIdx):
				cp.hashSlab254(myIdx, slab)
				cp.layerQueues[myIdx+1] <- slab
				pushedWork = true
			case twinHold != nil:
				copy(twinHold[32:64], slab[0:32])
				cp.hashSlab254(0, twinHold[0:64])
				cp.layerQueues[myIdx+1] <- twinHold[0:32:64]
				pushedWork = true
				twinHold = nil
			default:
				twinHold = slab[0:32:64]
			}

			// Check whether we need another worker
			//
			// n.b. we will not blow out of the preallocated layerQueues array,
			// as we disallow Write()s above a certain threshold
			if pushedWork && cp.layerQueues[myIdx+2] == nil {
				cp.addLayer(myIdx + 1)
			}
		}
	}()
}

func (cp *Calc) hashSlab254(layerIdx uint, slab []byte) {
	h := shaPool.Get().(hash.Hash)

	stride := 1 << (5 + layerIdx)
	for i := 0; len(slab) > i+stride; i += 2 * stride {
		h.Reset()
		h.Write(slab[i : i+32])
		h.Write(slab[i+stride : 32+i+stride])
		h.Sum(slab[i:i])[31] &= 0x3F // callers expect we will reuse-reduce-recycle
	}

	shaPool.Put(h)
}

// PadCommP is experimental, do not use it.
func PadCommP(sourceCommP []byte, sourcePaddedSize, targetPaddedSize uint64) ([]byte, error) {

	if len(sourceCommP) != 32 {
		return nil, xerrors.Errorf("provided commP must be exactly 32 bytes long, got %d bytes instead", len(sourceCommP))
	}
	if bits.OnesCount64(sourcePaddedSize) != 1 {
		return nil, xerrors.Errorf("source padded size %d is not a power of 2", sourcePaddedSize)
	}
	if bits.OnesCount64(targetPaddedSize) != 1 {
		return nil, xerrors.Errorf("target padded size %d is not a power of 2", targetPaddedSize)
	}
	if sourcePaddedSize > targetPaddedSize {
		return nil, xerrors.Errorf("source padded size %d larger than target padded size %d", sourcePaddedSize, targetPaddedSize)
	}
	if sourcePaddedSize < 128 {
		return nil, xerrors.Errorf("source padded size %d smaller than the minimum of 128 bytes", sourcePaddedSize)
	}
	if targetPaddedSize > MaxPieceSize {
		return nil, xerrors.Errorf("target padded size %d larger than Filecoin maximum of %d bytes", targetPaddedSize, MaxPieceSize)
	}

	// noop
	if sourcePaddedSize == targetPaddedSize {
		return sourceCommP, nil
	}

	out := make([]byte, 32)
	copy(out, sourceCommP)

	s := bits.TrailingZeros64(sourcePaddedSize)
	t := bits.TrailingZeros64(targetPaddedSize)

	h := shaPool.Get().(hash.Hash)
	for ; s < t; s++ {
		h.Reset()
		h.Write(out)
		h.Write(stackedNulPadding[s-5]) // account for 32byte chunks + off-by-one padding tower offset
		out = h.Sum(out[:0])
		out[31] &= 0x3F
	}
	shaPool.Put(h)

	return out, nil
}

////////////////////////////////////////////////////////////////////////

type CommonCarPragma struct {
	Version uint64
}

type CarV1Header struct {
	Version uint64
	Roots   []cid.Cid
}

const (
	// DefaultBufSize is the default buffer size used by the chunker.
	BufSize = ((4 << 20) / 128 * 127)
	// Pragma is the CARv2 pragma.
	Pragma = "0aa16776657273696f6e02"
	// PragmaSize is the size of the CARv2 pragma in bytes.
	PragmaSize = 11
	// HeaderSize is the fixed size of CARv2 header in number of bytes.
	HeaderSize = 40
	// CharacteristicsSize is the fixed size of Characteristics bitfield within CARv2 header in number of bytes.
	CharacteristicsSize = 16
)

// CarV2Header is the fixed-size header of a CARv2 file.
type CarV2Header struct {
	// Characteristics is a bitfield of characteristics that apply to the CARv2.
	Characteristics [16]byte
	// DataOffset is the byte offset from the beginning of the CARv2 to the beginning of the CARv1 data payload.
	DataOffset uint64
	// DataSize is the size of the CARv1 data payload in bytes.
	DataSize uint64
	// IndexOffset is the byte offset from the beginning of the CARv2 to the beginning of the CARv1 index payload.
	IndexOffset uint64
}

func init() {
	cbor.RegisterCborType(CarV1Header{})
}

func process(streamBuf *bufio.Reader, streamLen int64) (strLen int64, blockCount int64, err error) {
	for {
		maybeNextFrameLen, err := streamBuf.Peek(10)
		if err == io.EOF {
			break
		}
		if err != nil && err != bufio.ErrBufferFull {
			log.Fatalf("unexpected error at offset %d: %s", streamLen, err)
		}
		if len(maybeNextFrameLen) == 0 {
			log.Fatalf("impossible 0-length peek without io.EOF at offset %d", streamLen)
		}

		frameLen, viLen := binary.Uvarint(maybeNextFrameLen)
		if viLen <= 0 {
			// car file with trailing garbage behind it
			return streamLen, blockCount, fmt.Errorf("aborting car stream parse: undecodeable varint at offset %d", streamLen)
		}
		if frameLen > 2<<20 {
			// anything over ~2MiB got to be a mistake
			return streamLen, blockCount, fmt.Errorf("aborting car stream parse: unexpectedly large frame length of %d bytes at offset %d", frameLen, streamLen)
		}

		actualFrameLen, err := io.CopyN(io.Discard, streamBuf, int64(viLen)+int64(frameLen))
		streamLen += actualFrameLen
		if err != nil {
			if err != io.EOF {
				log.Fatalf("unexpected error at offset %d: %s", streamLen-actualFrameLen, err)
			}
			return streamLen, blockCount, fmt.Errorf("aborting car stream parse: truncated frame at offset %d: expected %d bytes but read %d: %s", streamLen-actualFrameLen, frameLen, actualFrameLen, err)
		}

		blockCount++
	}
	return streamLen, blockCount, nil
}

// checkCarV2 checks if the given file is a CARv2 file and returns the header if it is.
func checkCarV2(file io.ReadSeekCloser) (bool, *CarV2Header) {
	defer file.Seek(0, 0)
	// Read the first 11 bytes of the file into a byte slice
	pragmaHeader := make([]byte, 11)
	_, err := file.Read(pragmaHeader)
	if err != nil {
		fmt.Println("Error reading file:", err)
		panic(err)
	}

	carV2Header := &CarV2Header{}

	// Convert the expected header to a byte slice
	expectedHeader, err := hex.DecodeString(Pragma)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		panic(err)
	}
	// Compare the first 11 bytes of the file to the expected header
	if bytes.Equal(pragmaHeader, expectedHeader) {
		fmt.Println("File header matches expected header")
		// Read the next 40 bytes of the file into a byte slice
		header := make([]byte, 40)
		_, err = file.Read(header)
		if err != nil {
			fmt.Println("Error reading file:", err)
			panic(err)
		}

		// Read the characteristics
		copy(carV2Header.Characteristics[:], header[:16])

		// Read the data offset
		carV2Header.DataOffset = binary.LittleEndian.Uint64(header[16:24])

		// Read the data size
		carV2Header.DataSize = binary.LittleEndian.Uint64(header[24:32])

		// Read the index offset
		carV2Header.IndexOffset = binary.LittleEndian.Uint64(header[32:40])
		return true, carV2Header
	} else {
		fmt.Println("File header does not match expected header")
		return false, nil
	}
}

// extractCarV1 extracts the CARv1 data from a CARv2 file
func extractCarV1(file io.ReadSeekCloser, offset, length int) (*bytes.Reader, error) {
	// Slice out the portion of the file
	/*
		_, err := file.Seek(int64(offset), 0)
		if err != nil {
			return nil, err
		}
	*/
	slice := make([]byte, length)
	_, err := file.Read(slice)
	if err != nil {
		return nil, err
	}

	// Create a new io.Reader from the slice
	sliceReader := bytes.NewReader(slice)

	return sliceReader, nil
}

func main() {

	opts := &struct {
		Stdin        bool         `getopt:"-s --stdin               Read from stdin instead of a file"`
		PadPieceSize uint64       `getopt:"-p --pad-piece-size      Optional target power-of-two piece size, larger than the original input, one would like to pad to"`
		Help         options.Help `getopt:"-h --help                Display help"`
	}{}

	options.RegisterAndParse(opts)

	// Open the file
	var inp *os.File
	if opts.Stdin {
		// Read from stdin
		inp = os.Stdin
	} else {
		// Get the file name from the command-line arguments
		if len(os.Args) != 2 {
			fmt.Printf("Usage: %s <filename>\n", os.Args[0])
			return
		}
		fileName := os.Args[1]
		var err error
		inp, err = os.Open(fileName)
		if err != nil {
			panic(err)
		}
	}

	// Check if the file is a CARv2 file
	isCarV2, headerInfo := checkCarV2(inp)
	var streamBuf *bufio.Reader
	cp := new(Calc)
	if isCarV2 {
		// Extract the CARv1 data from the CARv2 file
		sliced, err := extractCarV1(inp, int(headerInfo.DataOffset), int(headerInfo.DataSize))
		if err != nil {
			panic(err)
		}
		streamBuf = bufio.NewReaderSize(
			io.TeeReader(sliced, cp),
			BufSize,
		)
	} else {
		// Read the file as a CARv1 file
		streamBuf = bufio.NewReaderSize(
			io.TeeReader(inp, cp),
			BufSize,
		)
	}

	var streamLen, blockCount int64
	var brokenCar bool
	var carHdr *CarV1Header

	// Read the first 10 bytes of the file into a byte slice
	headerLengthBytes, err := streamBuf.Peek(10)
	if err != nil {
		panic(err)
	}
	// Read the header length
	headerLength, headerBytesRead := binary.Uvarint(headerLengthBytes)
	if headerLength == 0 || headerBytesRead < 0 {
		panic(err)
	}
	// Read the header
	actualViLen, err := io.CopyN(io.Discard, streamBuf, int64(headerBytesRead))
	if err != nil {
		panic(err)
	}
	streamLen += actualViLen
	headerBuffer := make([]byte, headerLength)
	actualHdrLen, err := io.ReadFull(streamBuf, headerBuffer)
	if err != nil {
		panic(err)
	}
	streamLen += int64(actualHdrLen)

	// Decode the header
	carHeader := new(CarV1Header)
	err = cbor.DecodeInto(headerBuffer, carHeader)
	if err != nil {
		panic(err)
	}

	fmt.Println("carHeader.Version: ", carHeader.Version)

	if carHeader.Version == 1 || carHeader.Version == 2 {
		streamLen, blockCount, err = process(streamBuf, streamLen)
		if err != nil {
			log.Fatal(err)
			panic(err)
		}
	} else {
		panic(err)
	}

	/*
		if maybeHeaderLen, err := streamBuf.Peek(10); err == nil {
			if hdrLen, viLen := binary.Uvarint(maybeHeaderLen); viLen > 0 && hdrLen > 0 {
				actualViLen, err := io.CopyN(io.Discard, streamBuf, int64(viLen))
				streamLen += actualViLen
				if err == nil {
					hdrBuf := make([]byte, hdrLen)
					actualHdrLen, err := io.ReadFull(streamBuf, hdrBuf)
					streamLen += int64(actualHdrLen)
					if err == nil {
						carHdr = new(CarV1Header)
						if cbor.DecodeInto(hdrBuf, carHdr) != nil {
							// if it fails - it fails
							carHdr = nil
						} else if carHdr.Version == 1 {
							streamLen, blockCount, err = process(streamBuf, streamLen)
							if err != nil {
								log.Fatal(err)
								brokenCar = true
							}
						} else if carHdr.Version == 2 {
							fmt.Println("car v2")
							// readV1ContentFromV2Carfile(streamBuf)
							//streamBuf.Discard(PragmaSize + HeaderSize)

							streamLen, blockCount, err = process(streamBuf, streamLen)
							if err != nil {
								log.Fatal(err)
								brokenCar = true
							}
						} else {
							// if it fails - it fails
							carHdr = nil
						}
					}
				}
			}
		}
	*/

	// read out remainder into the hasher, if any
	n, err := io.Copy(io.Discard, streamBuf)
	streamLen += n
	if err != nil && err != io.EOF {
		log.Fatalf("unexpected error at offset %d: %s", streamLen, err)
	}

	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		log.Fatal(err)
	}

	if opts.PadPieceSize > 0 {
		rawCommP, err = PadCommP(
			rawCommP,
			paddedSize,
			opts.PadPieceSize,
		)
		if err != nil {
			log.Fatal(err)
		}
		paddedSize = opts.PadPieceSize
	}

	commCid, err := commcid.DataCommitmentV1ToCID(rawCommP)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, `
CommPCid: %s
Payload:        % 12d bytes
Unpadded piece: % 12d bytes
Padded piece:   % 12d bytes
`,
		commCid,
		streamLen,
		paddedSize/128*127,
		paddedSize,
	)

	// we got a header, funny that!
	if carHdr != nil {
		var maybeInvalidText string
		if brokenCar {
			maybeInvalidText = "*CORRUPTED* "
		}

		rootsText := make([]byte, 0, 2048)

		if len(carHdr.Roots) > 0 {
			// rootsText = append(rootsText, '\n')
			for i, c := range carHdr.Roots {
				rootsText = append(
					rootsText,
					fmt.Sprintf("% 5d: %s\n", i+1, c.String())...,
				)
			}
		}

		fmt.Fprintf(os.Stderr, `
%sCARv%d detected in stream:
Blocks:  % 8d
Roots:   % 8d
%s
`,
			maybeInvalidText,
			carHdr.Version,
			blockCount,
			len(carHdr.Roots),
			rootsText,
		)
	}
}
