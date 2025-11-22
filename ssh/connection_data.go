package ssh

import "crypto/ecdh"

type ConnectionState struct {
	ClientVersion []byte
	ServerVersion []byte

	ClientKexInit []byte
	ServerKexInit []byte

	ServerHostKey   []byte
	ClientEphemeral *ecdh.PrivateKey
	ServerEphemeral *ecdh.PublicKey

	SharedSecret []byte

	ExchangeHash []byte
	SessionId    []byte

	IVClientToServer  []byte
	IVServerToClient  []byte
	KeyClientToServer []byte
	KeyServerToClient []byte
	MACClientToServer []byte
	MACServerToClient []byte
}
