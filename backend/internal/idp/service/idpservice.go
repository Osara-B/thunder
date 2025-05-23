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

// Package service provides the implementation for IdP management operations.
package service

import (
	"errors"

	"github.com/asgardeo/thunder/internal/idp/model"
	"github.com/asgardeo/thunder/internal/idp/store"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/utils"
)

// IdPServiceInterface defines the interface for the IdP service.
type IdPServiceInterface interface {
	CreateIdP(idP *model.IdP) (*model.IdP, error)
	GetIdPList() ([]model.IdP, error)
	GetIdP(idPID string) (*model.IdP, error)
	UpdateIdP(idPID string, idP *model.IdP) (*model.IdP, error)
	DeleteIdP(idPID string) error
}

// IdPService is the default implementation of the IdPServiceInterface.
type IdPService struct{}

// GetIdPService creates a new instance of IdPService.
func GetIdPService() IdPServiceInterface {
	return &IdPService{}
}

// CreateIdP creates the IdP.
func (is *IdPService) CreateIdP(idP *model.IdP) (*model.IdP, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "IdPService"))

	idP.ID = utils.GenerateUUID()

	// Create the IdP in the database.
	err := store.CreateIdP(*idP)
	if err != nil {
		logger.Error("Failed to create IdP", log.Error(err))
		return nil, err
	}
	return idP, nil
}

// GetIdPList list the IdPs.
func (is *IdPService) GetIdPList() ([]model.IdP, error) {
	idPs, err := store.GetIdPList()
	if err != nil {
		return nil, err
	}

	return idPs, nil
}

// GetIdP get the IdP for given IdP id.
func (is *IdPService) GetIdP(idPID string) (*model.IdP, error) {
	if idPID == "" {
		return nil, errors.New("IdP ID is empty")
	}

	idP, err := store.GetIdP(idPID)
	if err != nil {
		return nil, err
	}

	return &idP, nil
}

// UpdateIdP update the IdP for given IdP id.
func (is *IdPService) UpdateIdP(idPID string, idP *model.IdP) (*model.IdP, error) {
	if idPID == "" {
		return nil, errors.New("IdP ID is empty")
	}

	err := store.UpdateIdP(idP)
	if err != nil {
		return nil, err
	}

	return idP, nil
}

// DeleteIdP delete the IdP for given IdP id.
func (is *IdPService) DeleteIdP(idPID string) error {
	if idPID == "" {
		return errors.New("IdP ID is empty")
	}

	err := store.DeleteIdP(idPID)
	if err != nil {
		return err
	}

	return nil
}
