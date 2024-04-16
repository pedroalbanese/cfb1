package CFB1

import "crypto/cipher"

type CFB1 struct {
	c         cipher.Block
	blockSize int
	iv, tmp   []byte
	de        bool
}

func NewCFB1Decrypt(c cipher.Block, iv []byte) *CFB1 {
	cp := make([]byte, len(iv))
	copy(cp, iv)
	return &CFB1{
		c:         c,
		blockSize: c.BlockSize(),
		iv:        cp,
		tmp:       make([]byte, c.BlockSize()),
		de:        true,
	}
}

func NewCFB1Encrypt(c cipher.Block, iv []byte) *CFB1 {
	cp := make([]byte, len(iv))
	copy(cp, iv)
	return &CFB1{
		c:         c,
		blockSize: c.BlockSize(),
		iv:        cp,
		tmp:       make([]byte, c.BlockSize()),
		de:        false,
	}
}

func (cf *CFB1) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		val := src[i]
		copy(cf.tmp, cf.iv)
		cf.c.Encrypt(cf.iv, cf.iv)
		val = val ^ cf.iv[0]

		copy(cf.iv, cf.tmp[1:])
		if cf.de {
			cf.iv[cf.blockSize-1] = src[i]
		} else {
			cf.iv[cf.blockSize-1] = val
		}

		dst[i] = val
	}
}
