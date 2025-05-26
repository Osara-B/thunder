/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package idp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	testServerURL = "https://localhost:8095"
)

var (
	preCreatedIdP = IdP{
		ID:           "550e8400-e29b-41d4-a716-446655440000",
		Name:         "Github",
		Description:  "Login with Github",
		ClientID:     "client1",
		ClientSecret: "secret1",
		RedirectURI:  "https://localhost:8090/flow/authn",
		Scopes:       json.RawMessage(`["user:email","read:user"]`),
	}

    preCreatedIdPToList = IdP{
    	ID:           "550e8400-e29b-41d4-a716-446655440000",
    	Name:         "Github",
    	Description:  "Login with Github",
    	ClientID:     "client1",
    	Scopes:       json.RawMessage(`["user:email","read:user"]`),
    }

	idPToCreate = IdP{
		ID:           "550e8400-e29b-41d4-a716-446655440001",
		Name:         "Google",
		Description:  "Google User Login",
		ClientID:     "client2",
		ClientSecret: "secret2",
		RedirectURI:  "https://localhost:8090/flow/authn2",
		Scopes:       json.RawMessage(`["user:email","read:user"]`),
	}

	idPToUpdate = IdP{
		ID:           "550e8400-e29b-41d4-a716-446655440000",
		Name:         "Github",
		Description:  "Github User Login",
		ClientID:     "client3",
		ClientSecret: "secret3",
		RedirectURI:  "https://localhost:8090/flow/authn3",
		Scopes:       json.RawMessage(`["user:email","read:user"]`),
	}
)

var createdIdPID string

type IdPAPITestSuite struct {
	suite.Suite
}

func TestIdPAPITestSuite(t *testing.T) {

	suite.Run(t, new(IdPAPITestSuite))
}

// SetupSuite test IdP creation
func (ts *IdPAPITestSuite) SetupSuite() {

	id, err := createIdP(ts)
	if err != nil {
		ts.T().Fatalf("Failed to create IdP during setup: %v", err)
	} else {
		createdIdPID = id
	}
}

// TearDownSuite test IdP deletion
func (ts *IdPAPITestSuite) TearDownSuite() {

	if createdIdPID != "" {
		err := deleteIdP(createdIdPID)
		if err != nil {
			ts.T().Fatalf("Failed to delete IdP during tear down: %v", err)
		}
	}
}

// Test IdP listing
func (ts *IdPAPITestSuite) TestIdPListing() {

	req, err := http.NewRequest("GET", testServerURL+"/identity-providers", nil)
	if err != nil {
		ts.T().Fatalf("Failed to create request: %v", err)
	}

	// Configure the HTTP client to skip TLS verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Validate the response
	if resp.StatusCode != http.StatusOK {
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Parse the response body
	var idPs []IdP
	err = json.NewDecoder(resp.Body).Decode(&idPs)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	idPListLength := len(idPs)
	if idPListLength == 0 {
		ts.T().Fatalf("Response does not contain any identity providers")
	}

	if idPListLength != 2 {
		ts.T().Fatalf("Expected 2 identity providers, got %d", idPListLength)
	}

	idP1 := idPs[0]
	if !idP1.equals(preCreatedIdPToList) {
		ts.T().Fatalf("IdP mismatch, expected %+v, got %+v", preCreatedIdPToList, idP1)
	}

	idP2 := idPs[1]
	createdIdP := buildCreatedIdPToList()
	if !idP2.equals(createdIdP) {
		ts.T().Fatalf("IdP mismatch, expected %+v, got %+v", createdIdP, idP2)
	}
}

// Test idP get by ID
func (ts *IdPAPITestSuite) TestIdPGetByID() {

	if createdIdPID == "" {
		ts.T().Fatal("IdP ID is not available for retrieval")
	}
	idP := buildCreatedIdP()
	retrieveAndValidateIdPDetails(ts, idP)
}

// Test idP update
func (ts *IdPAPITestSuite) TestIdPUpdate() {

	if createdIdPID == "" {
		ts.T().Fatal("IdP ID is not available for update")
	}

	idPJSON, err := json.Marshal(idPToUpdate)
	if err != nil {
		ts.T().Fatalf("Failed to marshal idPToUpdate: %v", err)
	}

	reqBody := bytes.NewReader(idPJSON)
	req, err := http.NewRequest("PUT", testServerURL+"/identity-providers/"+createdIdPID, reqBody)
	if err != nil {
		ts.T().Fatalf("Failed to create update request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send update request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Validate the update by retrieving the idP
	retrieveAndValidateIdPDetails(ts, IdP{
		ID:           createdIdPID,
		Name:         idPToUpdate.Name,
		Description:  idPToUpdate.Description,
		ClientID:     idPToUpdate.ClientID,
		RedirectURI:  idPToUpdate.RedirectURI,
		Scopes:       idPToUpdate.Scopes,
	})
}

func retrieveAndValidateIdPDetails(ts *IdPAPITestSuite, expectedIdP IdP) {

	req, err := http.NewRequest("GET", testServerURL+"/identity-providers/"+expectedIdP.ID, nil)
	if err != nil {
		ts.T().Fatalf("Failed to create get request: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		ts.T().Fatalf("Failed to send get request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ts.T().Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check if the response Content-Type is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		rawBody, _ := io.ReadAll(resp.Body)
		ts.T().Fatalf("Unexpected Content-Type: %s. Raw body: %s", contentType, string(rawBody))
	}

	var idP IdP
	err = json.NewDecoder(resp.Body).Decode(&idP)
	if err != nil {
		ts.T().Fatalf("Failed to parse response body: %v", err)
	}

	if !idP.equals(expectedIdP) {
		ts.T().Fatalf("IdP mismatch, expected %+v, got %+v", expectedIdP, idP)
	}
}

func createIdP(ts *IdPAPITestSuite) (string, error) {

	idPJSON, err := json.Marshal(idPToCreate)
	if err != nil {
		ts.T().Fatalf("Failed to marshal idPToCreate: %v", err)
	}

	reqBody := bytes.NewReader(idPJSON)
	req, err := http.NewRequest("POST", testServerURL+"/identity-providers", reqBody)
	if err != nil {
		// print error
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("expected status 201, got %d", resp.StatusCode)
	}

	var respBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	id, ok := respBody["id"].(string)
	if !ok {
		return "", fmt.Errorf("response does not contain id")
	}
	createdIdPID = id
	return id, nil
}

func deleteIdP(idPId string) error {

	req, err := http.NewRequest("DELETE", testServerURL+"/identity-providers/"+idPId, nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return err
	}
	return nil
}

func buildCreatedIdP() IdP {

	return IdP{
		ID:          createdIdPID,
		Name:        idPToCreate.Name,
		Description: idPToCreate.Description,
		ClientID:    idPToCreate.ClientID,
		RedirectURI: idPToCreate.RedirectURI,
		Scopes:      idPToCreate.Scopes,
	}
}

func buildCreatedIdPToList() IdP {

	return IdP{
		ID:          createdIdPID,
		Name:        idPToCreate.Name,
		Description: idPToCreate.Description,
		ClientID:    idPToCreate.ClientID,
		Scopes:      idPToCreate.Scopes,
	}
}
