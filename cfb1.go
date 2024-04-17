package CFB1

package main

import (
	"crypto/cipher"
)

type cfb1 struct {
	b       cipher.Block
	in      []byte
	out     []byte
	decrypt bool
}

func (x *cfb1) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cryptobin/cfb1: output smaller than input")
	}

	for i := range src {
		for j := 0; j < 8; j++ {
			x.b.Encrypt(x.out, x.in)

			outbit := (x.out[0] >> 7) & 1
			srcbit := (src[i] >> uint(7-j)) & 1

			dstbit := outbit ^ srcbit

			var movebit byte
			if x.decrypt {
				movebit = srcbit
			} else {
				movebit = dstbit
			}

			x.in = leftShiftBytes(x.in, movebit)

			if dstbit == 1 {
				dst[i] |= (1 << uint(7-j))
			} else {
				dst[i] &= ^(1 << uint(7-j))
			}

		}
	}
}

func leftShiftBytes(bytes []byte, carry byte) []byte {
	if len(bytes) == 1 {
		shiftedByte := (bytes[0] << 1) | carry
		return []byte{shiftedByte}
	}

	shiftedBytes := make([]byte, len(bytes))

	for i := 0; i < len(bytes)-1; i++ {
		currByte := bytes[i]
		nextByte := bytes[i+1]

		shiftedBytes[i] = (currByte << 1) | ((nextByte >> 7) & 1)
	}

	lastByte := (bytes[len(bytes)-1] << 1) | carry
	shiftedBytes[len(bytes)-1] = lastByte

	return shiftedBytes
}

func NewCFB1(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		panic("cryptobin/cfb1: IV length must equal block size")
	}

	x := &cfb1{
		b:       block,
		in:      make([]byte, blockSize),
		out:     make([]byte, blockSize),
		decrypt: decrypt,
	}
	copy(x.in, iv)

	return x
}

func NewCFB1Encrypt(block cipher.Block, iv []byte) cipher.Stream {
	return NewCFB1(block, iv, false)
}

func NewCFB1Decrypt(block cipher.Block, iv []byte) cipher.Stream {
	return NewCFB1(block, iv, true)
}

