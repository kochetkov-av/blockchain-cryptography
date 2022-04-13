package main

import (
	"bytes"
	"fmt"
	"log"
	"strconv"

	"github.com/ProtonMail/go-ecvrf/ecvrf"
)

func main() {
	privateKey, _ := ecvrf.GenerateKey(nil)
	publicKey, _ := privateKey.Public()

	counter := map[byte]int{}

	var once bool

	for i := 0; i < 256*30; i++ {
		seed := []byte("seed " + strconv.Itoa(i))

		vrf, proof, err := privateKey.Prove(seed)
		if err != nil {
			log.Fatal(err)
		}
		// vrf - pseudo-random value

		verified, verificationVRF, err := publicKey.Verify(seed, proof)
		if err != nil {
			log.Fatal(err)
		}

		if !verified || !bytes.Equal(vrf, verificationVRF) {
			log.Fatal("!")
		}

		counter[vrf[0]]++

		if !once {
			fmt.Printf("SK=%x\nPK=%x\nVRF=%x\nPROOF=%x\n\n", privateKey.Bytes(), publicKey.Bytes(), vrf, proof)
			once = true
		}
	}

	fmt.Println(counter)
}
