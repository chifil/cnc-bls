package bls

import (
	"encoding/hex"
	"testing"
)

func TestSign(t *testing.T) {
	asm := new(AugSchemeMPL)

	sk := KeyGen(testSeed)

	sign := asm.Sign(sk, []byte("chuwt"))
	t.Log("signedMsg:", hex.EncodeToString(sign))

	t.Log("verify:", asm.Verify(sk.GetPublicKey(), []byte("chuwt"), sign))
}

func TestAggregate(t *testing.T) {
	asm := new(AugSchemeMPL)

	masterSk := KeyGen(testSeed)

	farmerSk := masterSk.FarmerSk()
	farmerPk := farmerSk.GetPublicKey()

	poolSk := masterSk.PoolSk()
	poolPk := poolSk.GetPublicKey()

	// sign
	sig1 := asm.Sign(farmerSk, []byte("chuwt1"))
	sig2 := asm.Sign(poolSk, []byte("chuwt2"))
	t.Log("sig1:", hex.EncodeToString(sig1))
	t.Log("sig2:", hex.EncodeToString(sig2))
	aggSig, err := asm.Aggregate(sig1, sig2)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Aggregate:", hex.EncodeToString(aggSig))

	// Aggregate
	t.Log("AggregateVerify:", asm.AggregateVerify(
		[][]byte{
			farmerPk.Bytes(),
			poolPk.Bytes(),
		},
		[][]byte{
			[]byte("chuwt1"),
			[]byte("chuwt2"),
		},
		aggSig,
	))
}


func TestAggreSign(t *testing.T) {
	foo,_ :=hex.DecodeString("3a0463dd5fb221a977798af8b4be2f8c36aaeabcf830b155b942873e05e9d385")
	bar,_ :=hex.DecodeString("71845949cd1a7cd11868171f1c5aed2ac89270a12a3aefc263e3c7b966d943e1")
	fooPrivateKey := KeyFromBytes(foo)
	barPrivateKey := KeyFromBytes(bar)
	fooPublicKey := fooPrivateKey.GetPublicKey()
	barPublicKey := barPrivateKey.GetPublicKey()

	fooMessage := []byte("hello foo")
	barMessage := []byte("hello bar!")

	fooSign := (&AugSchemeMPL{}).Sign(fooPrivateKey, fooMessage)
	barSign := (&AugSchemeMPL{}).Sign(barPrivateKey, barMessage)

	aggregate, _ := (&AugSchemeMPL{}).Aggregate(fooSign, barSign)

	t.Log("AggregateVerify:", (&AugSchemeMPL{}).AggregateVerify(
		[][]byte{
			fooPublicKey.Bytes(),
			barPublicKey.Bytes(),
		}, [][]byte{
			fooMessage,
			barMessage,
		}, aggregate))
}
