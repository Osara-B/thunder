// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"

	resourcepkg "github.com/thunder-id/thunderid/internal/resource"
	"github.com/thunder-id/thunderid/internal/system/security"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// revokedPermissions returns what a change from current to next takes away, as the permission
// strings an already-issued token could be carrying.
//
// Every revocation on a role goes through here, whether it drops one permission, deletes the role,
// or removes whoever held it, so that the same change always revokes the same thing. Passing a nil
// next means the role grants nothing afterwards.
//
// Two things separate this from a set difference. A permission the role stops listing is not taken
// away if what the role still grants covers it, so dropping a child while keeping its parent
// revokes nothing. And a permission the role stops granting takes its subtree with it: tokens were
// issued for the permissions beneath it by name, so revoking only the name that was dropped would
// leave those working until they expired. Both reduce to coverage rather than equality.
//
// On a resource server whose permissions do not nest, coverage is equality and this is the set
// difference it always was.
func revokedPermissions(
	ctx context.Context, resourceService resourcepkg.ResourceServiceInterface,
	current, next []ResourcePermissions,
) ([]ResourcePermissions, *tidcommon.ServiceError) {
	delimiters := newPermissionDelimiterResolver(resourceService)

	kept := map[string][]string{}
	for _, resource := range next {
		kept[resource.ResourceServerID] = append(kept[resource.ResourceServerID], resource.Permissions...)
	}

	revoked := []ResourcePermissions{}
	for _, resource := range current {
		delimiter := delimiters.resolve(ctx, resource.ResourceServerID)
		stillGranted := func(permission string) bool {
			return security.AnyPermissionCovers(kept[resource.ResourceServerID], permission, delimiter)
		}

		removed := []string{}
		for _, permission := range resource.Permissions {
			if !stillGranted(permission) {
				removed = append(removed, permission)
			}
		}
		if len(removed) == 0 {
			continue
		}

		if delimiter != "" {
			descendants, svcErr := catalogueDescendants(
				ctx, resourceService, resource.ResourceServerID, removed, delimiter)
			if svcErr != nil {
				return nil, svcErr
			}
			for _, descendant := range descendants {
				if !stillGranted(descendant) {
					removed = append(removed, descendant)
				}
			}
		}

		revoked = append(revoked, ResourcePermissions{
			ResourceServerID: resource.ResourceServerID,
			Permissions:      removed,
		})
	}
	return revoked, nil
}

// catalogueDescendants returns the resource server's declared permissions that sit beneath any of
// the given ones.
//
// It reads the catalogue rather than deriving the strings, because only the catalogue knows which
// descendants exist. A token can only be carrying a permission the resource server declares, so
// nothing outside it needs revoking. This runs on administrative changes to a role, not on the
// authorization path.
func catalogueDescendants(
	ctx context.Context, resourceService resourcepkg.ResourceServiceInterface,
	resourceServerID string, permissions []string, delimiter string,
) ([]string, *tidcommon.ServiceError) {
	declared, svcErr := declaredPermissions(ctx, resourceService, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}

	descendants := []string{}
	seen := map[string]bool{}
	for _, permission := range permissions {
		for _, candidate := range declared {
			if candidate == permission || seen[candidate] {
				continue
			}
			if security.PermissionCovers(permission, candidate, delimiter) {
				seen[candidate] = true
				descendants = append(descendants, candidate)
			}
		}
	}
	return descendants, nil
}

// declaredPermissions lists every permission string a resource server declares, across its
// resources and the actions on and beneath them.
func declaredPermissions(
	ctx context.Context, resourceService resourcepkg.ResourceServiceInterface, resourceServerID string,
) ([]string, *tidcommon.ServiceError) {
	resources, svcErr := resourceService.GetAllResourceList(ctx, resourceServerID)
	if svcErr != nil {
		return nil, svcErr
	}

	permissions := make([]string, 0, len(resources))
	for _, resource := range resources {
		if resource.Permission != "" {
			permissions = append(permissions, resource.Permission)
		}
	}

	// Actions are listed per owner: the resource server itself, then each of its resources. They
	// are usually the leaves, so leaving them out would miss most of what a dropped parent covers.
	owners := make([]*string, 0, len(resources)+1)
	owners = append(owners, nil)
	for _, resource := range resources {
		if resource.ID != "" {
			owners = append(owners, &resource.ID)
		}
	}

	for _, owner := range owners {
		actions, svcErr := allActions(ctx, resourceService, resourceServerID, owner)
		if svcErr != nil {
			return nil, svcErr
		}
		for _, action := range actions {
			if action.Permission != "" {
				permissions = append(permissions, action.Permission)
			}
		}
	}

	return permissions, nil
}

// allActions pages through every action an owner declares.
func allActions(
	ctx context.Context, resourceService resourcepkg.ResourceServiceInterface,
	resourceServerID string, resourceID *string,
) ([]providers.Action, *tidcommon.ServiceError) {
	const pageSize = 100

	actions := []providers.Action{}
	for offset := 0; ; offset += pageSize {
		page, svcErr := resourceService.GetActionList(ctx, resourceServerID, resourceID, "", pageSize, offset)
		if svcErr != nil {
			return nil, svcErr
		}
		if page == nil {
			return actions, nil
		}
		actions = append(actions, page.Actions...)
		if len(page.Actions) < pageSize || len(actions) >= page.TotalResults {
			return actions, nil
		}
	}
}
