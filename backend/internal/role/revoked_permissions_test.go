// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/resource"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
	"github.com/thunder-id/thunderid/tests/mocks/resourcemock"
)

type RevokedPermissionsTestSuite struct {
	suite.Suite
	resources *resourcemock.ResourceServiceInterfaceMock
}

func TestRevokedPermissionsTestSuite(t *testing.T) {
	suite.Run(t, new(RevokedPermissionsTestSuite))
}

func (s *RevokedPermissionsTestSuite) SetupTest() {
	s.resources = resourcemock.NewResourceServiceInterfaceMock(s.T())
}

// stubMatching declares a resource server whose permissions do not nest.
func (s *RevokedPermissionsTestSuite) stubExact(id string) {
	s.resources.On("GetResourceServer", mock.Anything, id).
		Return(&providers.ResourceServer{ID: id, Delimiter: ":"}, nil)
}

// stubHierarchical declares a resource server whose permissions nest, along with its catalogue.
func (s *RevokedPermissionsTestSuite) stubHierarchical(id string, resources []providers.Resource,
	actionsByOwner map[string][]providers.Action) {
	s.resources.On("GetResourceServer", mock.Anything, id).
		Return(&providers.ResourceServer{ID: id, Delimiter: ":", HierarchicalPermissions: true}, nil)
	s.resources.On("GetAllResourceList", mock.Anything, id).Return(resources, nil)

	s.resources.On("GetActionList", mock.Anything, id, (*string)(nil), mock.Anything, mock.Anything, mock.Anything).
		Return(actionList(actionsByOwner[""]), nil)
	for _, res := range resources {
		owner := res.ID
		s.resources.On("GetActionList", mock.Anything, id, &owner, mock.Anything, mock.Anything, mock.Anything).
			Return(actionList(actionsByOwner[owner]), nil)
	}
}

func actionList(actions []providers.Action) *resource.ActionList {
	return &resource.ActionList{TotalResults: len(actions), Count: len(actions), Actions: actions}
}

func (s *RevokedPermissionsTestSuite) TestExactServerRevokesOnlyWhatWasDropped() {
	s.stubExact(californiaRSID)

	revoked, svcErr := revokedPermissions(context.Background(), s.resources,
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license", "permits"}}},
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"permits"}}})

	s.Require().Nil(svcErr)
	s.Equal([]ResourcePermissions{
		{ResourceServerID: californiaRSID, Permissions: []string{"license"}},
	}, revoked)
}

func (s *RevokedPermissionsTestSuite) TestNothingDroppedRevokesNothing() {
	s.stubExact(californiaRSID)

	revoked, svcErr := revokedPermissions(context.Background(), s.resources,
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license"}}},
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license", "permits"}}})

	s.Require().Nil(svcErr)
	s.Empty(revoked)
}

// Dropping a parent has to take the permissions beneath it with it, since tokens were issued for
// those by name and revoking only the parent would leave them working until they expired.
func (s *RevokedPermissionsTestSuite) TestDroppedParentRevokesItsSubtree() {
	s.stubHierarchical(californiaRSID,
		[]providers.Resource{{ID: "res-1", Permission: "license"}},
		map[string][]providers.Action{
			"res-1": {{Permission: "license:create"}, {Permission: "license:view"}},
			"":      {{Permission: "permits:view"}},
		})

	revoked, svcErr := revokedPermissions(context.Background(), s.resources,
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license"}}},
		[]ResourcePermissions{})

	s.Require().Nil(svcErr)
	s.Require().Len(revoked, 1)
	s.ElementsMatch([]string{"license", "license:create", "license:view"}, revoked[0].Permissions)
}

// Dropping a child while the role still grants its parent takes nothing away, because the parent
// still confers it. Revoking it would cut off access the role still means to give.
func (s *RevokedPermissionsTestSuite) TestDroppedChildCoveredByKeptParentRevokesNothing() {
	s.resources.On("GetResourceServer", mock.Anything, californiaRSID).
		Return(&providers.ResourceServer{ID: californiaRSID, Delimiter: ":", HierarchicalPermissions: true}, nil)

	revoked, svcErr := revokedPermissions(context.Background(), s.resources,
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license", "license:create"}}},
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license"}}})

	s.Require().Nil(svcErr)
	s.Empty(revoked)
}

// A subtree the role keeps part of is revoked only down to what it stopped granting.
func (s *RevokedPermissionsTestSuite) TestSubtreeRevocationSubtractsWhatIsStillGranted() {
	s.stubHierarchical(californiaRSID,
		[]providers.Resource{{ID: "res-1", Permission: "license"}},
		map[string][]providers.Action{
			"res-1": {{Permission: "license:create"}, {Permission: "license:view"}},
		})

	revoked, svcErr := revokedPermissions(context.Background(), s.resources,
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license"}}},
		[]ResourcePermissions{{ResourceServerID: californiaRSID, Permissions: []string{"license:view"}}})

	s.Require().Nil(svcErr)
	s.Require().Len(revoked, 1)
	s.ElementsMatch([]string{"license", "license:create"}, revoked[0].Permissions)
}
