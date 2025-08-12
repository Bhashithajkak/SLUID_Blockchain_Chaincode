package chaincode

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract provides functions for managing digital identity
type SmartContract struct {
	contractapi.Contract
}

// BlockchainIdentity contains only critical, immutable data stored on blockchain
type BlockchainIdentity struct {
	NIC                 string `json:"nic"`                 // Primary key - National Identity Card Number
	FullNameHash        string `json:"fullNameHash"`        // SHA256 hash of full name
	DateOfBirth         string `json:"dateOfBirth"`         // Exact DOB needed for age verification
	Gender              string `json:"gender"`              // Required for official documents
	BiometricHash       string `json:"biometricHash"`       // Critical for identity verification
	IssuedDate          string `json:"issuedDate"`          // When identity was issued
	IssuedBy            string `json:"issuedBy"`            // Issuing authority
	Status              string `json:"status"`              // Active, Suspended, Revoked
	PublicKey           string `json:"publicKey"`           // For digital signatures
	CertificateHash     string `json:"certificateHash"`    // Hash of digital certificate
	DocumentsIPFSHash   string `json:"documentsIPFSHash"`   // IPFS hash pointing to encrypted documents
	PersonalDataHash    string `json:"personalDataHash"`    // Hash of personal data stored in DB
	CreatedAt           string `json:"createdAt"`           // Blockchain record creation time
	LastUpdated         string `json:"lastUpdated"`         // Last modification time
	Version             int    `json:"version"`             // For version control
}

// IdentityVerification contains verification-specific data
type IdentityVerification struct {
	NIC           string `json:"nic"`
	VerifiedBy    string `json:"verifiedBy"`    // Organization that verified
	VerifiedAt    string `json:"verifiedAt"`    // Verification timestamp
	VerificationType string `json:"verificationType"` // Biometric, Document, etc.
	IsValid       bool   `json:"isValid"`
}

// InitLedger adds a base set of identities to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	identities := []BlockchainIdentity{
		{
			NIC:                 "920112345V",
			FullNameHash:        s.hashString("Amanda Jayasekara"),
			DateOfBirth:         "1992-01-12",
			Gender:              "Female",
			BiometricHash:       "e3b0c44298fc1c149afbf4c8996fb924",
			IssuedDate:          "2025-01-01",
			IssuedBy:           "Dept. of Registration",
			Status:             "Active",
			PublicKey:          "",
			CertificateHash:    "",
			DocumentsIPFSHash:  "",
			PersonalDataHash:   "",
			CreatedAt:          time.Now().Format(time.RFC3339),
			LastUpdated:        time.Now().Format(time.RFC3339),
			Version:            1,
		},
		{
			NIC:                 "900223456V",
			FullNameHash:        s.hashString("Nimal Perera"),
			DateOfBirth:         "1990-02-23",
			Gender:              "Male",
			BiometricHash:       "af1c0427c2cf9278e7ac1b89a4c8a9b2",
			IssuedDate:          "2025-01-05",
			IssuedBy:           "Dept. of Registration",
			Status:             "Active",
			PublicKey:          "",
			CertificateHash:    "",
			DocumentsIPFSHash:  "",
			PersonalDataHash:   "",
			CreatedAt:          time.Now().Format(time.RFC3339),
			LastUpdated:        time.Now().Format(time.RFC3339),
			Version:            1,
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

// CreateIdentity creates a new blockchain identity record
func (s *SmartContract) CreateIdentity(ctx contractapi.TransactionContextInterface, 
	nic string, fullNameHash string, dateOfBirth string, gender string, 
	biometricHash string, issuedDate string, issuedBy string, status string,
	publicKey string, certificateHash string, documentsIPFSHash string, 
	personalDataHash string) error {
	
	// Restrict to authorized organizations
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" && clientMSPID != "GovtMSP" {
		return fmt.Errorf("access denied: only authorized organizations can create identities")
	}

	// Check if identity already exists
	exists, err := s.IdentityExists(ctx, nic)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("identity with NIC %s already exists", nic)
	}

	// Validate NIC format (Sri Lankan format)
	if !s.isValidNIC(nic) {
		return fmt.Errorf("invalid NIC format: %s", nic)
	}

	identity := BlockchainIdentity{
		NIC:                nic,
		FullNameHash:       fullNameHash,
		DateOfBirth:        dateOfBirth,
		Gender:             gender,
		BiometricHash:      biometricHash,
		IssuedDate:         issuedDate,
		IssuedBy:          issuedBy,
		Status:            status,
		PublicKey:         publicKey,
		CertificateHash:   certificateHash,
		DocumentsIPFSHash: documentsIPFSHash,
		PersonalDataHash:  personalDataHash,
		CreatedAt:         time.Now().Format(time.RFC3339),
		LastUpdated:       time.Now().Format(time.RFC3339),
		Version:           1,
	}

	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nic, identityJSON)
}

// ReadIdentity returns the blockchain identity record
func (s *SmartContract) ReadIdentity(ctx contractapi.TransactionContextInterface, nic string) (*BlockchainIdentity, error) {
	identityJSON, err := ctx.GetStub().GetState(nic)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if identityJSON == nil {
		return nil, fmt.Errorf("identity %s does not exist", nic)
	}

	var identity BlockchainIdentity
	err = json.Unmarshal(identityJSON, &identity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity JSON: %v", err)
	}

	return &identity, nil
}

// UpdateIdentityStatus updates only the status and critical fields
func (s *SmartContract) UpdateIdentityStatus(ctx contractapi.TransactionContextInterface, 
	nic string, status string, reason string) error {
	
	// Restrict to authorized organizations
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" && clientMSPID != "GovtMSP" {
		return fmt.Errorf("access denied: only authorized organizations can update identity status")
	}

	// Get existing identity
	identity, err := s.ReadIdentity(ctx, nic)
	if err != nil {
		return err
	}

	// Update only status-related fields
	identity.Status = status
	identity.LastUpdated = time.Now().Format(time.RFC3339)
	identity.Version++

	// Create audit trail
	auditData := map[string]interface{}{
		"action":    "status_update",
		"oldStatus": identity.Status,
		"newStatus": status,
		"reason":    reason,
		"timestamp": time.Now().Format(time.RFC3339),
		"updatedBy": clientMSPID,
	}
	
	auditJSON, _ := json.Marshal(auditData)
	auditKey := fmt.Sprintf("AUDIT_%s_%d", nic, time.Now().Unix())
	ctx.GetStub().PutState(auditKey, auditJSON)

	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nic, identityJSON)
}

// UpdateIdentityHashes updates hash references when off-chain data changes
func (s *SmartContract) UpdateIdentityHashes(ctx contractapi.TransactionContextInterface,
	nic string, documentsIPFSHash string, personalDataHash string) error {
	
	// Restrict to authorized organizations
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client's MSP ID: %v", err)
	}
	if clientMSPID != "Org1MSP" && clientMSPID != "GovtMSP" {
		return fmt.Errorf("access denied: only authorized organizations can update identity hashes")
	}

	identity, err := s.ReadIdentity(ctx, nic)
	if err != nil {
		return err
	}

	identity.DocumentsIPFSHash = documentsIPFSHash
	identity.PersonalDataHash = personalDataHash
	identity.LastUpdated = time.Now().Format(time.RFC3339)
	identity.Version++

	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(nic, identityJSON)
}

// VerifyIdentity creates a verification record
func (s *SmartContract) VerifyIdentity(ctx contractapi.TransactionContextInterface,
	nic string, verifiedBy string, verificationType string) error {
	
	// Check if identity exists
	exists, err := s.IdentityExists(ctx, nic)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("identity %s does not exist", nic)
	}

	verification := IdentityVerification{
		NIC:              nic,
		VerifiedBy:       verifiedBy,
		VerifiedAt:       time.Now().Format(time.RFC3339),
		VerificationType: verificationType,
		IsValid:          true,
	}

	verificationJSON, err := json.Marshal(verification)
	if err != nil {
		return err
	}

	verificationKey := fmt.Sprintf("VERIFY_%s_%d", nic, time.Now().Unix())
	return ctx.GetStub().PutState(verificationKey, verificationJSON)
}

// GetIdentityHistory returns the modification history of an identity
func (s *SmartContract) GetIdentityHistory(ctx contractapi.TransactionContextInterface, nic string) ([]map[string]interface{}, error) {
	resultsIterator, err := ctx.GetStub().GetHistoryForKey(nic)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var history []map[string]interface{}
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		record := map[string]interface{}{
			"txId":      response.TxId,
			"timestamp": response.Timestamp,
			"isDelete":  response.IsDelete,
			"value":     string(response.Value),
		}
		history = append(history, record)
	}

	return history, nil
}

// IdentityExists checks if an identity exists
func (s *SmartContract) IdentityExists(ctx contractapi.TransactionContextInterface, nic string) (bool, error) {
	data, err := ctx.GetStub().GetState(nic)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return data != nil, nil
}

// GetAllIdentities returns all identities (limited fields for privacy)
func (s *SmartContract) GetAllIdentities(ctx contractapi.TransactionContextInterface) ([]*BlockchainIdentity, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var identities []*BlockchainIdentity
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		// Skip audit and verification records
		if len(queryResponse.Key) > 10 {
			continue
		}

		var identity BlockchainIdentity
		err = json.Unmarshal(queryResponse.Value, &identity)
		if err != nil {
			continue
		}
		identities = append(identities, &identity)
	}

	return identities, nil
}

// Helper functions
func (s *SmartContract) hashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

func (s *SmartContract) isValidNIC(nic string) bool {
	// Basic Sri Lankan NIC validation
	if len(nic) == 10 && (nic[9] == 'V' || nic[9] == 'v' || nic[9] == 'X' || nic[9] == 'x') {
		return true
	}
	if len(nic) == 12 {
		return true
	}
	return false
}