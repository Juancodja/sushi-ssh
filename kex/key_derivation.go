package kex

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"

	"github.com/Juancodja/sushi-ssh/ssh"
)

func DerivateConnState(ks *KexState) (*ssh.ConnectionState, error) {
	K, err := DerivateShareSecret(ks.ClientEphemeral, ks.ServerEphemeral)
	if err != nil {
		return nil, err
	}

	H := DerivateExchangeHash(K, ks)

	id := make([]byte, len(H))
	copy(id, H)

	fmt.Printf("Hash: [% x]\n", H)
	return &ssh.ConnectionState{
		ClientVersion:     ks.ClientVersion,
		ServerVersion:     ks.ServerVersion,
		ClientKexInit:     ks.ClientKexInit,
		ServerKexInit:     ks.ServerKexInit,
		ServerHostKey:     ks.ServerHostKey,
		ClientEphemeral:   ks.ClientEphemeral,
		ServerEphemeral:   ks.ServerEphemeral,
		SharedSecret:      K,
		ExchangeHash:      H,
		SessionId:         id,
		IVClientToServer:  deriveKey(K, H, id, 'A'),
		IVServerToClient:  deriveKey(K, H, id, 'B'),
		KeyClientToServer: deriveKey(K, H, id, 'C'),
		KeyServerToClient: deriveKey(K, H, id, 'D'),
		MACClientToServer: deriveKey(K, H, id, 'E'),
		MACServerToClient: deriveKey(K, H, id, 'F'),
	}, nil
}

func DerivateShareSecret(clientPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey) ([]byte, error) {
	K, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Shared Secret: [% x]\n", K)
	return K, nil
}

func DerivateExchangeHash(k []byte, s *KexState) []byte {
	cv := ssh.EncodeSshString(s.ClientVersion).Marshal()
	sv := ssh.EncodeSshString(s.ServerVersion).Marshal()

	cInit := ssh.EncodeSshString(s.ClientKexInit).Marshal()
	sInit := ssh.EncodeSshString(s.ServerKexInit).Marshal()

	shk := ssh.EncodeSshString(s.ServerHostKey).Marshal()

	Qc := ssh.EncodeSshString(s.ClientEphemeral.Bytes()).Marshal()
	Qs := ssh.EncodeSshString(s.ServerEphemeral.Bytes()).Marshal()

	K := ssh.EncodeMpint(k).Marshal()

	blob := make([]byte, 0)
	blob = append(blob, cv...)
	blob = append(blob, sv...)
	blob = append(blob, cInit...)
	blob = append(blob, sInit...)
	blob = append(blob, shk...)
	blob = append(blob, Qc...)
	blob = append(blob, Qs...)
	blob = append(blob, K...)

	h := sha256.Sum256(blob)
	return h[:]
}

func deriveKey(k, h, id []byte, label byte) []byte {

	blob := make([]byte, 0)

	blob = append(blob, ssh.EncodeMpint(k).Marshal()...)
	blob = append(blob, h...)
	blob = append(blob, label)
	blob = append(blob, id...)

	key := sha256.Sum256(blob)
	return key[:]
}
