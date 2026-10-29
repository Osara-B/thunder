// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package role

import (
	"context"

	resourcepkg "github.com/thunder-id/thunderid/internal/resource"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// permissionDelimiterResolver answers, per resource server, which delimiter its permission strings nest
// on, or an empty string when they do not nest at all.
//
// Whether one permission confers another is a property of the resource server rather than of the
// string, so every comparison needs this answer first.
//
// Nothing is cached. The declaration can be turned on and off after the resource server is created,
// and it decides what every existing grant on that server confers, so a stale answer would keep
// authorizing by a relation the resource server has stopped declaring. The read is one indexed
// primary-key lookup on a small table, and invalidating it correctly would mean reaching back from
// the package that owns the write, against this package's import direction.
type permissionDelimiterResolver struct {
	resourceService resourcepkg.ResourceServiceInterface
}

func newPermissionDelimiterResolver(
	resourceService resourcepkg.ResourceServiceInterface,
) *permissionDelimiterResolver {
	return &permissionDelimiterResolver{resourceService: resourceService}
}

// resolve returns the delimiter the resource server's permissions nest on.
//
// An empty string is returned when the resource server is not named, when its permissions do not
// nest, or when it cannot be read. All three reduce matching to equality, which denies a permission
// an ancestor would have conferred rather than granting one, so an unreadable resource server
// refuses rather than guesses.
func (c *permissionDelimiterResolver) resolve(ctx context.Context, resourceServerID string) string {
	if c == nil || c.resourceService == nil || resourceServerID == "" {
		return ""
	}

	resourceServer, svcErr := c.resourceService.GetResourceServer(ctx, resourceServerID)
	if svcErr != nil || resourceServer == nil {
		log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName)).Debug(ctx,
			"Could not resolve the resource server delimiter; matching permissions exactly",
			log.String("resourceServerID", resourceServerID))
		return ""
	}

	if !resourceServer.HierarchicalPermissions {
		return ""
	}
	return resourceServer.Delimiter
}

// resolveAll returns the delimiter for each resource server named, omitting those whose permissions
// do not nest so that a caller indexing the result gets an empty delimiter for them.
func (c *permissionDelimiterResolver) resolveAll(
	ctx context.Context, resourceServerIDs []string,
) map[string]string {
	if len(resourceServerIDs) == 0 {
		return nil
	}
	delimiters := make(map[string]string, len(resourceServerIDs))
	for _, resourceServerID := range resourceServerIDs {
		if delimiter := c.resolve(ctx, resourceServerID); delimiter != "" {
			delimiters[resourceServerID] = delimiter
		}
	}
	return delimiters
}
