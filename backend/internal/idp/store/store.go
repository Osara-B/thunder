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

// Package store provides the implementation for IdP persistence operations.
package store

import (
	"encoding/json"
	"fmt"

	"github.com/asgardeo/thunder/internal/idp/model"
	"github.com/asgardeo/thunder/internal/system/database/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

// CreateIdP handles the IdP creation in the database.
func CreateIdP(idp model.IdP) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	// Convert scopes to JSON string
	scopes, err := json.Marshal(idp.Scopes)
	if err != nil {
		logger.Error("Failed to marshal scopes", log.Error(err))
		return model.ErrBadScopesInRequest
	}

	_, err = dbClient.Execute(QueryCreateIdP, idp.ID, idp.Name, idp.Description, idp.ClientID, idp.ClientSecret,
		idp.RedirectURI, string(scopes))
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	return nil
}

// GetIdPList retrieves a list of IdP from the database.
func GetIdPList() ([]model.IdP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPPersistence"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return nil, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetIdPList)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	idps := make([]model.IdP, 0)

	for _, row := range results {
		idp, err := buildIdPForListFromResultRow(row)
		if err != nil {
			logger.Error("failed to build idp from result row", log.Error(err))
			return nil, fmt.Errorf("failed to build idp from result row: %w", err)
		}
		idps = append(idps, idp)
	}

	return idps, nil
}

// GetIdP retrieves a specific idp by its ID from the database.
func GetIdP(id string) (model.IdP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return model.IdP{}, fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	results, err := dbClient.Query(QueryGetIdPByIdPID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return model.IdP{}, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(results) == 0 {
		logger.Error("idp not found with id: " + id)
		return model.IdP{}, model.ErrIdPNotFound
	}

	if len(results) != 1 {
		logger.Error("unexpected number of results")
		return model.IdP{}, fmt.Errorf("unexpected number of results: %d", len(results))
	}

	row := results[0]

	idp, err := buildIdPFromResultRow(row)
	if err != nil {
		logger.Error("failed to build idp from result row")
		return model.IdP{}, fmt.Errorf("failed to build idp from result row: %w", err)
	}
	return idp, nil
}

// UpdateIdP updates the idp in the database.
func UpdateIdP(idp *model.IdP) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	// Convert attributes to JSON string
	scopes, err := json.Marshal(idp.Scopes)
	if err != nil {
		logger.Error("Failed to marshal attributes", log.Error(err))
		return model.ErrBadScopesInRequest
	}

	rowsAffected, err := dbClient.Execute(QueryUpdateIdPByIdPID, idp.ID, idp.Name, idp.Description, idp.ClientID,
		idp.ClientSecret, idp.RedirectURI, string(scopes))
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("idp not found with id: " + idp.ID)
		return model.ErrIdPNotFound
	}

	return nil
}

// DeleteIdP deletes the idp from the database.
func DeleteIdP(id string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	dbClient, err := provider.NewDBProvider().GetDBClient("identity")
	if err != nil {
		logger.Error("Failed to get database client", log.Error(err))
		return fmt.Errorf("failed to get database client: %w", err)
	}
	defer func() {
		if closeErr := dbClient.Close(); closeErr != nil {
			logger.Error("Failed to close database client", log.Error(closeErr))
			err = fmt.Errorf("failed to close database client: %w", closeErr)
		}
	}()

	rowsAffected, err := dbClient.Execute(QueryDeleteIdPByIdPID, id)
	if err != nil {
		logger.Error("Failed to execute query", log.Error(err))
		return fmt.Errorf("failed to execute query: %w", err)
	}

	if rowsAffected == 0 {
		logger.Error("idp not found with id: " + id)
	}

	return nil
}

func buildIdPFromResultRow(row map[string]interface{}) (model.IdP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	idPID, ok := row["idp_id"].(string)
	if !ok {
		logger.Error("failed to parse idp_id as string")
		return model.IdP{}, fmt.Errorf("failed to parse idp_id as string")
	}

	idPName, ok := row["name"].(string)
	if !ok {
		logger.Error("failed to parse name as string")
		return model.IdP{}, fmt.Errorf("failed to parse name as string")
	}

	idPDescription, ok := row["description"].(string)
	if !ok {
		logger.Error("failed to parse description as string")
		return model.IdP{}, fmt.Errorf("failed to parse description as string")
	}

	idPClientID, ok := row["client_id"].(string)
	if !ok {
		logger.Error("failed to parse client_id as string")
		return model.IdP{}, fmt.Errorf("failed to parse client_id as string")
	}

	idPClientSecret, ok := row["client_secret"].(string)
	if !ok {
		logger.Error("failed to parse client_secret as string")
		return model.IdP{}, fmt.Errorf("failed to parse client_secret as string")
	}

	idPRedirectURI, ok := row["redirect_uri"].(string)
	if !ok {
		logger.Error("failed to parse redirect_uri as string")
		return model.IdP{}, fmt.Errorf("failed to parse redirect_uri as string")
	}

	var scopes string
	switch v := row["scopes"].(type) {
	case string:
		scopes = v
	case []byte:
		scopes = string(v) // Convert byte slice to string
	default:
		logger.Error("failed to parse scopes", log.Any("raw_value", row["scopes"]), log.String("type",
			fmt.Sprintf("%T", row["scopes"])))
		return model.IdP{}, fmt.Errorf("failed to parse scopes as string")
	}

	idp := model.IdP{
		ID:           idPID,
		Name:         idPName,
		Description:  idPDescription,
		ClientID:     idPClientID,
		ClientSecret: idPClientSecret,
		RedirectURI:  idPRedirectURI,
	}

	// Unmarshal JSON scopes
	if err := json.Unmarshal([]byte(scopes), &idp.Scopes); err != nil {
		logger.Error("Failed to unmarshal scopes")
		return model.IdP{}, fmt.Errorf("failed to unmarshal scopes")
	}

	return idp, nil
}

func buildIdPForListFromResultRow(row map[string]interface{}) (model.IdP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPStore"))

	idPID, ok := row["idp_id"].(string)
	if !ok {
		logger.Error("failed to parse idp_id as string")
		return model.IdP{}, fmt.Errorf("failed to parse idp_id as string")
	}

	idPName, ok := row["name"].(string)
	if !ok {
		logger.Error("failed to parse name as string")
		return model.IdP{}, fmt.Errorf("failed to parse name as string")
	}

	idPDescription, ok := row["description"].(string)
	if !ok {
		logger.Error("failed to parse description as string")
		return model.IdP{}, fmt.Errorf("failed to parse description as string")
	}

	idPClientID, ok := row["client_id"].(string)
	if !ok {
		logger.Error("failed to parse client_id as string")
		return model.IdP{}, fmt.Errorf("failed to parse client_id as string")
	}

	var scopes string
	switch v := row["scopes"].(type) {
	case string:
		scopes = v
	case []byte:
		scopes = string(v) // Convert byte slice to string
	default:
		logger.Error("failed to parse scopes", log.Any("raw_value", row["scopes"]), log.String("type",
			fmt.Sprintf("%T", row["scopes"])))
		return model.IdP{}, fmt.Errorf("failed to parse scopes as string")
	}

	idp := model.IdP{
		ID:          idPID,
		Name:        idPName,
		Description: idPDescription,
		ClientID:    idPClientID,
	}

	// Unmarshal JSON scopes
	if err := json.Unmarshal([]byte(scopes), &idp.Scopes); err != nil {
		logger.Error("Failed to unmarshal scopes")
		return model.IdP{}, fmt.Errorf("failed to unmarshal scopes")
	}

	return idp, nil
}
