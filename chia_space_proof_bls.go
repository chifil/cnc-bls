package bls

import "crypto/sha256"

const HashSize = 32

// CalculatePlotFilterInput return [32]byte
func CalculatePlotFilterInput(plotId ,challengeHash,signagePoint [HashSize]byte) []byte {
	bytes := make([]byte, 32*3)
	copy(bytes,plotId[:])
	copy(bytes[32:],challengeHash[:])
	copy(bytes[32*2:],signagePoint[:])
	return sha256.New().Sum(bytes)
}

// CalculatePosChallenge return [32]byte
func CalculatePosChallenge(plotId, challengeHash, signagePoint [HashSize]byte) []byte {
	return sha256.New().Sum(CalculatePlotFilterInput(plotId,challengeHash,signagePoint))
}

// CalculatePlotIdPk return [32]byte
func CalculatePlotIdPk(poolContractPuzzleHash, plotPublicKey PublicKey) []byte {
	return sha256.New().Sum(append(poolContractPuzzleHash.Bytes(), plotPublicKey.Bytes()...))
}

// CalculatePlotIdPh return [32]byte
func CalculatePlotIdPh(poolContractPuzzleHash [HashSize]byte, plotPublicKey PublicKey) []byte {
	return sha256.New().Sum(append(poolContractPuzzleHash[:], plotPublicKey.Bytes()...))
}

func GeneratePlotPublicKey(localPk, farmerPk PublicKey, includeTaproot bool) PublicKey {
	if includeTaproot {
		return localPk.Add(farmerPk).Add(GenerateTaprootSk(localPk, farmerPk).GetPublicKey())
	}
	return localPk.Add(farmerPk)
}

func GenerateTaprootSk(localPk, farmerPk PublicKey) PrivateKey {
	taprootKey := localPk.Add(farmerPk).Bytes()
	taprootKey = append(taprootKey, localPk.Bytes()...)
	taprootKey = append(taprootKey, farmerPk.Bytes()...)
	sum := sha256.New().Sum(taprootKey)
	return KeyGen(sum)
}

