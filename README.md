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
5. derive 生walletSk
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