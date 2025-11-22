package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type CipherContext struct {
	Conn    net.Conn
	Encrypt cipher.Stream
	MacKey  []byte
	SeqNum  uint32
}

func StartCipherWriter(wg *sync.WaitGroup, ctx *CipherContext, incoming <-chan []byte) {
	wg.Add(1)
	go func() {
		for p := range incoming {
			msg := NewSshMessage(p, aes.BlockSize)

			plain := msg.Marshal()

			fmt.Println(plain)

			encrypted := make([]byte, len(plain))
			ctx.Encrypt.XORKeyStream(encrypted, plain)

			mac := computeMac(ctx.MacKey, encrypted, ctx.SeqNum)

			pack := append(encrypted, mac...)

			_, err := ctx.Conn.Write(pack)
			if err != nil {
				fmt.Println("Error escribiendo mensaje cifrado", err)
				return
			}

			fmt.Println("Mensaje Enviado")
			ctx.SeqNum++
		}
	}()
}
func computeMac(macKey, msg []byte, seq uint32) []byte {
	h := hmac.New(sha256.New, macKey)

	var seqBuf [4]byte
	binary.BigEndian.PutUint32(seqBuf[:], seq)
	h.Write(seqBuf[:])
	h.Write(msg)

	return h.Sum(nil)
}
