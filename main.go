package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Payload struct {
	PAN string `json:"pan"`
	Exp string `json:"exp"`
	CVV string `json:"cvv"`
}

func main() {
	http.HandleFunc("/encrypt", encryptHandler)
	fmt.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the incoming JSON payload
	var payload Payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Create the ECDSA public key from the provided parameters
	pubKey, err := createPublicKey()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create public key: %v", err), http.StatusInternalServerError)
		return
	}

	// Encrypt the payload
	encryptedData, err := encryptPayload(payload, pubKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encrypt payload: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the encrypted data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"encrypted_data": encryptedData})
}

func createPublicKey() (*ecdsa.PublicKey, error) {
	// Base64URL-encoded X and Y coordinates (from your provided JSON)
	xBase64 := "UbInEqNbZZZ9SJptBwKTKO6qslSyuWvMkVK44Bx_d8U"
	yBase64 := "PUxeHMNVL0VRxOYJrkHcpe6sap7IG-Are0QborZDngI"

	// Decode base64url strings to big.Int
	xBytes, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %v", err)
	}

	// Convert decoded bytes into big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Construct the ECDSA public key using the P-256 curve
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

func encryptPayload(payload Payload, pubKey *ecdsa.PublicKey) (string, error) {
	// Marshal the payload into JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Create the JWK (JSON Web Key)
	jwkKey, err := jwk.FromRaw(pubKey) // Use jwk.FromRaw instead of jwk.New
	if err != nil {
		return "", err
	}

	// Set the key ID (kid) for the JWK
	if err := jwkKey.Set(jwk.KeyIDKey, "ASDsL-Jx2XOkRnFtqW-QblWY-mDnQW2LgapadFx75tA"); err != nil {
		return "", err
	}

	// Encrypt the payload using JWE
	encrypted, err := jwe.Encrypt(
		payloadJSON,                            // The payload (plaintext)
		jwe.WithKey(jwa.ECDH_ES, jwkKey),       // Key encryption algorithm and public key
		jwe.WithContentEncryption(jwa.A256GCM), // Content encryption algorithm
	)
	if err != nil {
		return "", err
	}

	// Return the encrypted data as a string
	return string(encrypted), nil
}
