package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
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
		KexAlgos:                   utils.NameList{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"},
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

	msg, _ = bufio.NewReader(conn).ReadString('\n')

	fmt.Println("SERVIDOR:", msg)

}
