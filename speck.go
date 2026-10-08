package speck

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// 64 bit blocks
type Speck64 struct {
	roundKeys []uint32
}

func (s Speck64) BlockSize() int {
	return 8
}

func eround32(x uint32, y uint32, k uint32) (uint32, uint32) {
	x = bits.RotateLeft32(x, -8)
	x += y
	x ^= k

	y = bits.RotateLeft32(y, 3)
	y ^= x

	return x, y
}

func dround32(x uint32, y uint32, k uint32) (uint32, uint32) {
	y ^= x
	y = bits.RotateLeft32(y, -3)

	x ^= k
	x -= y
	x = bits.RotateLeft32(x, 8)

	return x, y
}

func (s *Speck64) Encrypt(dst, src []byte) {
	a := binary.LittleEndian.Uint32(src[0:4])
	b := binary.LittleEndian.Uint32(src[4:8])

	for r := range 27 {
		b, a = eround32(b, a, s.roundKeys[r])
	}

	binary.LittleEndian.PutUint32(dst[0:4], a)
	binary.LittleEndian.PutUint32(dst[4:8], b)
}

func (s *Speck64) Decrypt(dst, src []byte) {
	a := binary.LittleEndian.Uint32(src[0:4])
	b := binary.LittleEndian.Uint32(src[4:8])

	for r := 26; r >= 0; r-- {
		b, a = dround32(b, a, s.roundKeys[r])
	}

	binary.LittleEndian.PutUint32(dst[0:4], a)
	binary.LittleEndian.PutUint32(dst[4:8], b)
}

func New64(key []byte) (*Speck64, error) {
	var speck Speck64

	if len(key) != 16 {
		return nil, errors.New("invalid key size.")
	}

	a := binary.LittleEndian.Uint32(key[0:4])
	b := binary.LittleEndian.Uint32(key[4:8])
	c := binary.LittleEndian.Uint32(key[8:12])
	d := binary.LittleEndian.Uint32(key[12:16])

	speck.roundKeys = make([]uint32, 0, 27)

	i := uint32(0)
	for i < 26 {
		speck.roundKeys = append(speck.roundKeys, a)
		b, a = eround32(b, a, i)
		i++

		speck.roundKeys = append(speck.roundKeys, a)
		c, a = eround32(c, a, i)
		i++

		speck.roundKeys = append(speck.roundKeys, a)
		d, a = eround32(d, a, i)
		i++
	}

	speck.roundKeys = append(speck.roundKeys, a)

	return &speck, nil
}

// 128 bit blocks
type Speck128 struct {
	keylen    int
	roundKeys []uint64
}

func (s Speck128) BlockSize() int {
	return 16
}

func eround64(x uint64, y uint64, k uint64) (uint64, uint64) {
	x = bits.RotateLeft64(x, -8)
	x += y
	x ^= k

	y = bits.RotateLeft64(y, 3)
	y ^= x

	return x, y
}

func dround64(x uint64, y uint64, k uint64) (uint64, uint64) {
	y ^= x
	y = bits.RotateLeft64(y, -3)

	x ^= k
	x -= y
	x = bits.RotateLeft64(x, 8)

	return x, y
}

func (s *Speck128) Encrypt(dst, src []byte) {
	rounds := 32
	if s.keylen == 32 {
		rounds = 34
	}

	a := binary.LittleEndian.Uint64(src[0:8])
	b := binary.LittleEndian.Uint64(src[8:16])

	for r := range rounds {
		b, a = eround64(b, a, s.roundKeys[r])
	}

	binary.LittleEndian.PutUint64(dst[0:8], a)
	binary.LittleEndian.PutUint64(dst[8:16], b)
}

func (s *Speck128) Decrypt(dst, src []byte) {
	a := binary.LittleEndian.Uint64(src[0:8])
	b := binary.LittleEndian.Uint64(src[8:16])

	rounds := 32

	if s.keylen == 32 {
		rounds = 34
	}

	for r := rounds - 1; r >= 0; r-- {
		b, a = dround64(b, a, s.roundKeys[r])
	}

	binary.LittleEndian.PutUint64(dst[0:8], a)
	binary.LittleEndian.PutUint64(dst[8:16], b)
}

func New128(key []byte) (*Speck128, error) {
	var speck Speck128

	speck.keylen = len(key)

	switch speck.keylen {
	case 16:
		a := binary.LittleEndian.Uint64(key[0:8])
		b := binary.LittleEndian.Uint64(key[8:16])

		for i := range 31 {
			speck.roundKeys = append(speck.roundKeys, a)
			b, a = eround64(b, a, uint64(i))
		}

		speck.roundKeys = append(speck.roundKeys, a)
	case 32:
		a := binary.LittleEndian.Uint64(key[0:8])
		b := binary.LittleEndian.Uint64(key[8:16])
		c := binary.LittleEndian.Uint64(key[16:24])
		d := binary.LittleEndian.Uint64(key[24:32])

		speck.roundKeys = make([]uint64, 0, 34)

		i := uint64(0)
		for i < 33 {
			speck.roundKeys = append(speck.roundKeys, a)
			b, a = eround64(b, a, i)
			i++

			speck.roundKeys = append(speck.roundKeys, a)
			c, a = eround64(c, a, i)
			i++

			speck.roundKeys = append(speck.roundKeys, a)
			d, a = eround64(d, a, i)
			i++
		}

		speck.roundKeys = append(speck.roundKeys, a)
	default:
		return nil, errors.New("invalid key size.")
	}

	return &speck, nil
}
