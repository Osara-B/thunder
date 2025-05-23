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

// Package handler provides the implementation for identity provider management operations.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/asgardeo/thunder/internal/idp/model"
	idpprovider "github.com/asgardeo/thunder/internal/idp/provider"
	"github.com/asgardeo/thunder/internal/system/log"
)

// IdPHandler is the handler for identity provider management operations.
type IdPHandler struct {
}

// HandleIdPPostRequest handles the post identity provider request.
func (ih *IdPHandler) HandleIdPPostRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPHandler"))

	var idPInCreationRequest model.IdP
	if err := json.NewDecoder(r.Body).Decode(&idPInCreationRequest); err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}

	// Create the IdP using the IdP service.
	idPProvider := idpprovider.NewIdPProvider()
	idPService := idPProvider.GetIdPService()
	createdIdP, err := idPService.CreateIdP(&idPInCreationRequest)
	if err != nil {
		if errors.Is(err, model.ErrBadScopesInRequest) {
			http.Error(w, "Bad Request: The scopes element is malformed or contains invalid data.", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(createdIdP)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP creation response.
	logger.Debug("IdP POST response sent", log.String("IdP id", createdIdP.ID))
}

// HandleIdPListRequest handles the get identity providers request.
func (ih *IdPHandler) HandleIdPListRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPHandler"))

	// Get the IdP list using the IdP service.
	idPProvider := idpprovider.NewIdPProvider()
	idPService := idPProvider.GetIdPService()
	idps, err := idPService.GetIdPList()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idps)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP GET (list) response sent")
}

// HandleIdPGetRequest handles the get identity provider request.
func (ih *IdPHandler) HandleIdPGetRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	// Get the IdP using the IdP service.
	idPProvider := idpprovider.NewIdPProvider()
	idPService := idPProvider.GetIdPService()
	idp, err := idPService.GetIdP(id)
	if err != nil {
		if errors.Is(err, model.ErrIdPNotFound) {
			http.Error(w, "Not Found: The identity provider with the specified id does not exist.", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	idpMap := map[string]interface{}{
		"id":           idp.ID,
		"name":         idp.Name,
		"description":  idp.Description,
		"client_id":    idp.ClientID,
		"redirect_uri": idp.RedirectURI,
		"scopes":       idp.Scopes,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idpMap)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP GET response sent", log.String("IdP id", id))
}

// HandleIdPPutRequest handles the put identity provider request.
func (ih *IdPHandler) HandleIdPPutRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	var updatedIdP model.IdP
	if err := json.NewDecoder(r.Body).Decode(&updatedIdP); err != nil {
		http.Error(w, "Bad Request: The request body is malformed or contains invalid data.", http.StatusBadRequest)
		return
	}
	updatedIdP.ID = id

	// Update the IdP using the IdP service.
	idPProvider := idpprovider.NewIdPProvider()
	idPService := idPProvider.GetIdPService()
	idp, err := idPService.UpdateIdP(id, &updatedIdP)
	if err != nil {
		if errors.Is(err, model.ErrIdPNotFound) {
			http.Error(w, "Not Found: The identity provider with the specified id does not exist.", http.StatusNotFound)
		} else if errors.Is(err, model.ErrBadScopesInRequest) {
			http.Error(w, "Bad Request: The attributes element is malformed or contains invalid data.", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(idp)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log the IdP response.
	logger.Debug("IdP PUT response sent", log.String("IdP id", id))
}

// HandleIdPDeleteRequest handles the delete identity provider request.
func (ih *IdPHandler) HandleIdPDeleteRequest(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPHandler"))

	id := strings.TrimPrefix(r.URL.Path, "/identity-providers/")
	if id == "" {
		http.Error(w, "Bad Request: Missing identity provider id.", http.StatusBadRequest)
		return
	}

	// Delete the IdP using the IdP service.
	idPProvider := idpprovider.NewIdPProvider()
	idPService := idPProvider.GetIdPService()
	err := idPService.DeleteIdP(id)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	// Log the IdP response.
	logger.Debug("IdP DELETE response sent", log.String("IdP id", id))
}
