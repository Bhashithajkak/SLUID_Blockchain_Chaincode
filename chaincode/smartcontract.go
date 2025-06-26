package chaincode

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract provides functions for managing an Identity
type SmartContract struct {
	contractapi.Contract
}

// Identity describes basic details of what makes up a simple identity
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically
type Identity struct {
	NIC             string `json:"nic"`             // National Identity Card Number (Unique ID)
	FullName        string `json:"fullName"`        // Full legal name
	DateOfBirth     string `json:"dateOfBirth"`     // In YYYY-MM-DD format
	Gender          string `json:"gender"`          // Male, Female, Other
	Address         string `json:"address"`         // Permanent address
	PhoneNumber     string `json:"phoneNumber"`     // Optional: Mobile number
	Email           string `json:"email"`           // Optional: email
	IssuedDate      string `json:"issuedDate"`      // Date identity was issued
	IssuedBy        string `json:"issuedBy"`        // e.g., "Dept. of Registration"
	BiometricHash   string `json:"biometricHash"`   // SHA hash of fingerprint/photo/etc.
	Status          string `json:"status"`          // e.g., "Active", "Suspended", "Revoked"
	PublicKey		string `json:"publicKey"`		// Public key associate with the user wallet
	WalletId		string `json:"walletId"`		// Wallet ID
	CertificateHash	string `json:"certificateHash"`	//
}

// InitLedger adds a base set of identites to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	identities := []Identity{
		{
			NIC:           "920112345V",
			FullName:      "Amanda Jayasekara",
			DateOfBirth:   "1992-01-12",
			Gender:        "Female",
			Address:       "No. 12, Temple Road, Colombo",
			PhoneNumber:   "+94771234567",
			Email:         "dhanushi@example.com",
			IssuedDate:    "2025-01-01",
			IssuedBy:      "Dept. of Registration",
			BiometricHash: "e3b0c44298fc1c149afbf4c8996...",
			Status:        "Active",
		},
		{
			NIC:           "900223456V",
			FullName:      "Nimal Perera",
			DateOfBirth:   "1990-02-23",
			Gender:        "Male",
			Address:       "123 Main Street, Kandy",
			PhoneNumber:   "+94781234567",
			Email:         "nimal@example.com",
			IssuedDate:    "2025-01-05",
			IssuedBy:      "Dept. of Registration",
			BiometricHash: "af1c0427c2cf9278e7ac1b89a4c...",
			Status:        "Active",
		},
	}

	for _, identity := range identities {
		identityJSON, err := json.Marshal(identity)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(identity.NIC, identityJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

// CreateIdentity adds a new identity to the ledger. Only Org1 is allowed to invoke this.
func (s *SmartContract) CreateIdentity(ctx contractapi.TransactionContextInterface, nic string, fullName string, dob string, gender string, address string, phone string, email string, issuedDate string, issuedBy string, biometricHash string, status string, publicKey string, walletId string, certificateHash string) error {
	
	// Restrict this function to Org1MSP
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" {
		return fmt.Errorf("access denied: only Org1MSP can create identities")
	}

	// Check if the identity already exists
	exists, err := s.IdentityExists(ctx, nic)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the identity with NIC %s already exists", nic)
	}

	identity := Identity{
		NIC:           	nic,
		FullName:      	fullName,
		DateOfBirth:   	dob,
		Gender:        	gender,
		Address:       	address,
		PhoneNumber:   	phone,
		Email:         	email,
		IssuedDate:    	issuedDate,
		IssuedBy:      	issuedBy,
		BiometricHash: 	biometricHash,
		Status:        	status,
		PublicKey:	   	publicKey,
		WalletId:		walletId,
		CertificateHash:certificateHash,
	}

	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nic, identityJSON)
}

// ReadIdentity returns the identity stored in the world state with the given NIC.
func (s *SmartContract) ReadIdentity(ctx contractapi.TransactionContextInterface, nic string) (*Identity, error) {
	identityJSON, err := ctx.GetStub().GetState(nic)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if identityJSON == nil {
		return nil, fmt.Errorf("the identity %s does not exist", nic)
	}

	var identity Identity
	err = json.Unmarshal(identityJSON, &identity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity JSON: %v", err)
	}

	return &identity, nil
}

// UpdateIdentity updates an existing identity in the world state with provided parameters.
func (s *SmartContract) UpdateIdentity(ctx contractapi.TransactionContextInterface, nic string, fullName string, dateOfBirth string, gender string, address string, phoneNumber string, email string, issuedDate string, issuedBy string, biometricHash string, status string) error {
	
	// Restrict this function to Org1MSP
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" {
		return fmt.Errorf("access denied: only Org1MSP can create identities")
	}
	
	// Check if the identity already exists
	exists, err := s.IdentityExists(ctx, nic)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the identity %s does not exist", nic)
	}

	identity := Identity{
		NIC:           nic,
		FullName:      fullName,
		DateOfBirth:   dateOfBirth,
		Gender:        gender,
		Address:       address,
		PhoneNumber:   phoneNumber,
		Email:         email,
		IssuedDate:    issuedDate,
		IssuedBy:      issuedBy,
		BiometricHash: biometricHash,
		Status:        status,
		// should add wallet and public key if necessary
	}

	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nic, identityJSON)
}

// DeleteIdentity deletes a given identity from the world state.
func (s *SmartContract) DeleteIdentity(ctx contractapi.TransactionContextInterface, nic string) error {

	// Restrict this function to Org1MSP
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" {
		return fmt.Errorf("access denied: only Org1MSP can create identities")
	}
	
	// Check if the identity already exists
	exists, err := s.IdentityExists(ctx, nic)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the identity %s does not exist", nic)
	}

	return ctx.GetStub().DelState(nic)
}


// IdentityExists checks whether an identity exists in the ledger.
func (s *SmartContract) IdentityExists(ctx contractapi.TransactionContextInterface, nic string) (bool, error) {
	data, err := ctx.GetStub().GetState(nic)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return data != nil, nil
}

// // TransferAsset updates the owner field of asset with given id in world state, and returns the old owner.
// func (s *SmartContract) TransferAsset(ctx contractapi.TransactionContextInterface, id string, newOwner string) (string, error) {
// 	asset, err := s.ReadAsset(ctx, id)
// 	if err != nil {
// 		return "", err
// 	}

// 	oldOwner := asset.Owner
// 	asset.Owner = newOwner

// 	assetJSON, err := json.Marshal(asset)
// 	if err != nil {
// 		return "", err
// 	}

// 	err = ctx.GetStub().PutState(id, assetJSON)
// 	if err != nil {
// 		return "", err
// 	}

// 	return oldOwner, nil
// }

// GetAllIdentities returns all identities found in the world state
func (s *SmartContract) GetAllIdentities(ctx contractapi.TransactionContextInterface) ([]*Identity, error) {
	// Range query with empty string for startKey and endKey retrieves all keys in the world state
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var identities []*Identity
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var identity Identity
		err = json.Unmarshal(queryResponse.Value, &identity)
		if err != nil {
			continue // skip invalid entries
		}
		identities = append(identities, &identity)
	}

	return identities, nil
}