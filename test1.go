package main

import (
	"crypto/rand"
	"log"
	"math/big"

	"github.com/1Password/srp"
	"github.com/gin-gonic/gin"
	"github.com/nitin06890/srp-auth.git/customkdf"
)

func main() {
	var err error
	var A, B *big.Int

	/*** Part 1: Enrollment ***/

	group := srp.RFC5054Group3072

	pw := "Shelby_7"

	salt := make([]byte, 8)
	n, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
	} else if n != 8 {
		log.Fatal("Failed to generate 8 byte salt")
	}

	username := "shelby@dummy.com"

	X := customkdf.KDF512(salt, username, pw)

	firstClient := srp.NewSRPClient(srp.KnownGroups[group], X, nil)

	if firstClient == nil {
		log.Fatal("Couldn't setup client")
	}
	V, err := firstClient.Verifier()
	if err != nil {
		log.Fatal(err)
	}

	/*** Part 2:  Authentication session ***/

	client := srp.NewSRPClient(srp.KnownGroups[group], X, nil)

	A = client.EphemeralPublic()
	server := srp.NewSRPServer(srp.KnownGroups[group], V, nil)
	if server == nil {
		log.Fatal("Couldn't set up server")
	}

	err = server.SetOthersPublic(A)
	if err != nil {
		log.Fatal(err)
	}

	B = server.EphemeralPublic()
	if B == nil {
		log.Fatal("server couldn't make B")
	}

	serverKey, err := server.Key()
	if err != nil || serverKey == nil {
		log.Fatalf("something went wrong making server key: %s\n", err)
	}

	err = client.SetOthersPublic(B)
	if err != nil {
		log.Fatal(err)
	}

	clientKey, err := client.Key()
	if err != nil || clientKey == nil {
		log.Fatalf("something went wrong making server key: %s", err)
	}

	/*** Part 3: Server and client prove they have the same key ***/

	serverProof, err := server.M(salt, username)
	if err != nil {
		log.Fatal(err)
	}

	if !client.GoodServerProof(salt, username, serverProof) {
		log.Fatal("bad proof from server")
	}

	clientProof, err := client.ClientProof()
	if err != nil {
		log.Fatal(err)
	}

	if !server.GoodClientProof(clientProof) {
		log.Fatal("bad proof from client")
	}

	router := gin.Default()

	router.POST("/test", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"message": "Succesfully Authenticated",
		})
	})

	router.Run(":8080")
}
