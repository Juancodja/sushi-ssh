package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Juancodja/sushi-ssh/kex"
	"github.com/Juancodja/sushi-ssh/utils"
)

func main() {
	fmt.Println("🍣 Bienvenido al proyecto Sushi!")

	conn, err := net.Dial("tcp", "localhost:2222")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	version := "SSH-2.0-SUSHI"
	fmt.Println("CLIENTE: ", version)

	fmt.Fprint(conn, version+"\r\n")

	msg, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("SERVIDOR:", msg)

	var c [16]byte
	rand.Read(c[:])
	ckinit := kex.KexInit{
		MessageCode:                20,
		Cookie:                     c,
		KexAlgos:                   utils.NameList{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "curve25519-sha256"},
		ServerHostKeyAlgos:         utils.NameList{"ssh-rsa", "ssh-dss"},
		EncryptionClientToServer:   utils.NameList{"3des-cbc"},
		EncryptionServerToClient:   utils.NameList{"3des-cbc"},
		MacClientToServer:          utils.NameList{"hmac-sha1"},
		MacServerToClient:          utils.NameList{"hmac-sha1"},
		CompressionClientToServer:  utils.NameList{"none"},
		CompressionServertToClient: utils.NameList{"none"},
		LanguagesClientToServer:    utils.NameList{},
		LanguagesServerToClient:    utils.NameList{},
		FirstKexPacketFollows:      false,
		EmptyField:                 0,
	}

	fmt.Println("CLIENTE: SSH_MSG_KEXINIT")

	fmt.Printf("%+v\n", ckinit)

	m := utils.NewSSHMessage(ckinit.Marshal(), []byte{}, 8)

	fmt.Fprint(conn, m)

	var packlen uint32
	binary.Read(conn, binary.BigEndian, &packlen)

	var padlen byte
	binary.Read(conn, binary.BigEndian, &padlen)

	payload_len := int(packlen) - int(padlen) - 1
	payload := make([]byte, payload_len)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		panic(err)
	}

	skinit, _ := kex.UnmarshalKexInit(payload)

	fmt.Printf("%+v\n", skinit)

	kexAlg := "none"
	for _, v1 := range ckinit.KexAlgos {
		for _, v2 := range skinit.KexAlgos {
			if v2 == v1 {
				kexAlg = v2
				break
			}
		}
	}
	if kexAlg == "none" {
		panic("no hay algorimo valido")
	}
	fmt.Println("ALGORITMO KEX SELECIONADO: ")
	fmt.Println(kexAlg)
}
