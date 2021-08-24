# cnc-bls
bls lib for golang

## Feature
- generate private key
  - mnemonic
  - seed
  - hexString
  - bytes
- sign
- sign verify
- multiple sign
- multiple sign verify

## install
```
go get github.com/cnc-project/cnc-bls
```

## instructions for use

### Example

```go
package main

import (
  "fmt"
  cb "github.com/cnc-project/cnc-bls"
)

func main(){
  // Generate a mnemonic for memorization or user-friendly seeds
  entropy, _ := cb.NewEntropy()
  mnemonic, _ := cb.NewMnemonic(entropy)

  // Generate a Bip32 HD wallet for the mnemonic and a user supplied password
  seed := cb.NewSeed(mnemonic, "Secret Passphrase")

  priKey := cb.KeyGen(seed)
  publicKey := priKey.GetPublicKey()

  // Display mnemonic and keys
  fmt.Println("Mnemonic: ", mnemonic)
  fmt.Println("Master private key: ", priKey)
  fmt.Println("Master public key: ", publicKey)
  fmt.Println("Master generate fingerprint", publicKey.FingerPrint())
}
```

### load private key
1. mnemonic loading
```
func KeyGenWithMnemonic(mnemonic, password string) PrivateKey
```
2. load hex string 
```
func KeyFromHexString(key string) (PrivateKey, error)
```
3. load bytes
```
func KeyFromHexString(key string) (PrivateKey, error)
```
### PrivateKey
1. generate bytes
```
func (key PrivateKey) Bytes() []byte
```
2. generate hex string
```
func (key PrivateKey) Hex() string
```
3. derive farmerSk
```
func (key PrivateKey) FarmerSk() PrivateKey
```
4. derive poolSk
```
func (key PrivateKey) PoolSk() PrivateKey 
```
5. derive walletSk
```
func (key PrivateKey) WalletSk(index int) PrivateKey
```
6. derive localSk
```
func (key PrivateKey) LocalSk() PrivateKey
```
7. generate SyntheticSk
```
func (key PrivateKey) SyntheticSk(hiddenPuzzleHash []byte) PrivateKey
```
8. generate public key
```
func (key PrivateKey) GetPublicKey() PublicKey
```

### PublicKey
1. generate fingerprint
```
func (key PublicKey) FingerPrint() string
```
2. generate bytes
```
func (key PublicKey) Bytes() []byte
```
3. generate hex string
```
func (key PublicKey) Hex() string
```

### Signature
1. sign
```
func (asm *AugSchemeMPL) Sign(sk PrivateKey, message []byte)
```
2. verify
```
func (asm *AugSchemeMPL) Verify(pk PublicKey, message []byte, sig []byte) bool
```
3. multiple sign
```
// Combine multiple signatures together
func (asm *AugSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error)
```
4. multiple sign verify
```
// Public key array, original information array, data returned by multi-signature
func (asm *AugSchemeMPL) AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) bool
```