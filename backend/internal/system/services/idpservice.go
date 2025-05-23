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

package services

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/idp/handler"
	"github.com/asgardeo/thunder/internal/system/server"
)

// IdPService is the service for identity provider management operations.
type IdPService struct {
	idPHandler *handler.IdPHandler
}

// NewIdPService creates a new instance of IdPService.
func NewIdPService(mux *http.ServeMux) *IdPService {
	instance := &IdPService{
		idPHandler: &handler.IdPHandler{},
	}
	instance.RegisterRoutes(mux)

	return instance
}

// RegisterRoutes registers the routes for identity provider operations.
//
//nolint:dupl // Ignoring false positive duplicate code
func (s *IdPService) RegisterRoutes(mux *http.ServeMux) {
	opts1 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, POST",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	server.WrapHandleFunction(mux, "POST /identity-providers", &opts1, s.idPHandler.HandleIdPPostRequest)
	server.WrapHandleFunction(mux, "GET /identity-providers", &opts1, s.idPHandler.HandleIdPListRequest)
	server.WrapHandleFunction(mux, "OPTIONS /identity-providers", &opts1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	opts2 := server.RequestWrapOptions{
		Cors: &server.Cors{
			AllowedMethods:   "GET, PUT, DELETE",
			AllowedHeaders:   "Content-Type, Authorization",
			AllowCredentials: true,
		},
	}
	server.WrapHandleFunction(mux, "GET /identity-providers/", &opts2, s.idPHandler.HandleIdPGetRequest)
	server.WrapHandleFunction(mux, "PUT /identity-providers/", &opts2, s.idPHandler.HandleIdPPutRequest)
	server.WrapHandleFunction(mux, "DELETE /identity-providers/", &opts2, s.idPHandler.HandleIdPDeleteRequest)
	server.WrapHandleFunction(mux, "OPTIONS /identity-providers/", &opts2, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}
