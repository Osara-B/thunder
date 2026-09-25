// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package ouprovider

import (
	"context"

	"github.com/thunder-id/thunderid/internal/ou"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// ouProvider exposes the organization unit service through the runtime provider contract.
type ouProvider struct {
	ouService ou.OrganizationUnitServiceInterface
}

// newOUProvider creates an ouProvider backed by the given organization unit service.
func newOUProvider(ouService ou.OrganizationUnitServiceInterface) providers.OrganizationUnitProvider {
	return &ouProvider{ouService: ouService}
}

// GetOrganizationUnit returns the runtime view of the organization unit with the given ID.
func (p *ouProvider) GetOrganizationUnit(
	ctx context.Context, id string,
) (providers.OrganizationUnit, *tidcommon.ServiceError) {
	orgUnit, svcErr := p.ouService.GetOrganizationUnit(ctx, id)
	if svcErr != nil {
		return providers.OrganizationUnit{}, svcErr
	}
	return toProviderOU(orgUnit), nil
}

// CreateOrganizationUnit provisions an organization unit from a runtime request.
func (p *ouProvider) CreateOrganizationUnit(
	ctx context.Context, request providers.OrganizationUnitRequestWithID,
) (providers.OrganizationUnit, *tidcommon.ServiceError) {
	orgUnit, svcErr := p.ouService.CreateOrganizationUnit(ctx, toServiceRequest(request))
	if svcErr != nil {
		return providers.OrganizationUnit{}, svcErr
	}
	return toProviderOU(orgUnit), nil
}

// IsParent reports whether parentID is an ancestor of childID.
func (p *ouProvider) IsParent(
	ctx context.Context, parentID, childID string,
) (bool, *tidcommon.ServiceError) {
	return p.ouService.IsParent(ctx, parentID, childID)
}

// IsOrganizationUnitExists reports whether an organization unit with the given ID exists.
func (p *ouProvider) IsOrganizationUnitExists(
	ctx context.Context, id string,
) (bool, *tidcommon.ServiceError) {
	return p.ouService.IsOrganizationUnitExists(ctx, id)
}

// GetOrganizationUnitChildren returns a page of the organization unit's direct children.
func (p *ouProvider) GetOrganizationUnitChildren(
	ctx context.Context, id string, limit, offset int, f *tidcommon.FilterGroup,
) (*providers.OrganizationUnitListResponse, *tidcommon.ServiceError) {
	children, svcErr := p.ouService.GetOrganizationUnitChildren(ctx, id, limit, offset, f)
	if svcErr != nil {
		return nil, svcErr
	}
	return toProviderList(children), nil
}

// toProviderOU maps the management organization unit onto the runtime view.
func toProviderOU(orgUnit ou.OrganizationUnit) providers.OrganizationUnit {
	return providers.OrganizationUnit{
		ID:              orgUnit.ID,
		Handle:          orgUnit.Handle,
		Name:            orgUnit.Name,
		Description:     orgUnit.Description,
		LogoURL:         orgUnit.LogoURL,
		TosURI:          orgUnit.TosURI,
		PolicyURI:       orgUnit.PolicyURI,
		CookiePolicyURI: orgUnit.CookiePolicyURI,
	}
}

// toServiceRequest maps a runtime provisioning request onto the management request.
func toServiceRequest(request providers.OrganizationUnitRequestWithID) ou.OrganizationUnitRequestWithID {
	return ou.OrganizationUnitRequestWithID{
		ID:          request.ID,
		Handle:      request.Handle,
		Name:        request.Name,
		Description: request.Description,
		Parent:      request.Parent,
	}
}

// toProviderList maps a management list response onto the runtime view. Pagination links are a
// management API concern and are not carried across.
func toProviderList(list *ou.OrganizationUnitListResponse) *providers.OrganizationUnitListResponse {
	if list == nil {
		return nil
	}
	units := make([]providers.OrganizationUnitBasic, 0, len(list.OrganizationUnits))
	for _, unit := range list.OrganizationUnits {
		units = append(units, providers.OrganizationUnitBasic{
			ID:          unit.ID,
			Handle:      unit.Handle,
			Name:        unit.Name,
			Description: unit.Description,
		})
	}
	return &providers.OrganizationUnitListResponse{
		TotalResults:      list.TotalResults,
		StartIndex:        list.StartIndex,
		Count:             list.Count,
		OrganizationUnits: units,
	}
}
