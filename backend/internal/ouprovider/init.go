// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package ouprovider adapts the organization unit management service to the runtime provider
// contract, mapping the management model onto the narrower view the OAuth and flow layers consume.
package ouprovider

import (
	"github.com/thunder-id/thunderid/internal/ou"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// Initialize creates the default OrganizationUnitProvider backed by the organization unit service.
func Initialize(ouService ou.OrganizationUnitServiceInterface) providers.OrganizationUnitProvider {
	return newOUProvider(ouService)
}
