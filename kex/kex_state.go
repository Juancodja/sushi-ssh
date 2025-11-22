package kex

import "crypto/ecdh"

type KexState struct {
	ClientVersion []byte
	ServerVersion []byte

	ClientKexInit []byte
	ServerKexInit []byte

	ServerHostKey   []byte
	ClientEphemeral *ecdh.PrivateKey
	ServerEphemeral *ecdh.PublicKey
}
