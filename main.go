package main

import(
	"go-aes-encryption-example/utils"
	"fmt"
)


func main() {
	enc := utils.NewAes()
	ciphertext := "CYKQ+Id2N2O/UGmCBcGxkxw5jabj7kgfkvEz97+ZEbIHyyo="
	plaintext, _ := enc.Decrypt(ciphertext)
	fmt.Printf("The plaintext for %s is %s\n", ciphertext, plaintext)
}