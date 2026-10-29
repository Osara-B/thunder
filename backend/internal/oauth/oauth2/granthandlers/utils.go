// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/revocation"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	oauth2utils "github.com/thunder-id/thunderid/internal/oauth/oauth2/utils"
	"github.com/thunder-id/thunderid/internal/system/security"
)

// excludeRevokedScopes returns the OIDC scopes and the permission scopes not revoked since a grant was
// established, refusing the grant when it was revoked itself, when revocation leaves no scope to grant, or
// when the deny list cannot be read.
func excludeRevokedScopes(ctx context.Context, enforcementService revocation.EnforcementServiceInterface,
	grant revocation.RevocationIdentity, subject string, audiences, oidcScopes, scopes []string,
) ([]string, *model.ErrorResponse) {
	// Nil only when oauth.token_revocation is disabled, as the token validator also treats it.
	if enforcementService == nil {
		return slices.Concat(oidcScopes, scopes), nil
	}
	// Second precision, like a token's iat, so a revocation within the grant's issuing second applies.
	grant.EstablishedAt = grant.EstablishedAt.UTC().Truncate(time.Second)

	// One lookup answers the common case; only a match is narrowed to the grant or the revoked scopes.
	err := enforcementService.EnsureNotRevoked(ctx, revocation.RevocationIdentity{
		EstablishedAt: grant.EstablishedAt,
		Criteria:      append(revocation.ScopeCriteria(subject, audiences, scopes), grant.Criteria...),
	})
	if err == nil {
		return slices.Concat(oidcScopes, scopes), nil
	}
	if !errors.Is(err, revocation.ErrTokenRevoked) {
		return nil, grantRevocationError(err)
	}
	if err := enforcementService.EnsureNotRevoked(ctx, grant); err != nil {
		return nil, grantRevocationError(err)
	}

	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		err := enforcementService.EnsureNotRevoked(ctx, revocation.RevocationIdentity{
			EstablishedAt: grant.EstablishedAt,
			Criteria:      revocation.ScopeCriteria(subject, audiences, []string{scope}),
		})
		if err == nil {
			kept = append(kept, scope)
		} else if !errors.Is(err, revocation.ErrTokenRevoked) {
			return nil, grantRevocationError(err)
		}
	}
	// A response without scope reads as granted as requested (RFC 6749 §5.1), so nothing left is a refusal.
	if len(oidcScopes) == 0 && len(kept) == 0 {
		return nil, grantRevocationError(revocation.ErrTokenRevoked)
	}
	return slices.Concat(oidcScopes, kept), nil
}

// grantRevocationError maps a deny-list result to the token error refusing the grant.
func grantRevocationError(err error) *model.ErrorResponse {
	if errors.Is(err, revocation.ErrTokenRevoked) {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "The authorization grant has been revoked",
		}
	}
	return &model.ErrorResponse{
		Error:            constants.ErrorServerError,
		ErrorDescription: "Token revocation status could not be verified",
	}
}

// oidcScopeSet returns the subset of scopes that are OIDC scopes for this application, as a set for
// repeated lookup.
func oidcScopeSet(scopes []string, scopeClaims map[string][]string) map[string]struct{} {
	oidcScopes, _ := oauth2utils.SeparateOIDCAndNonOIDCScopes(tokenservice.JoinScopes(scopes), scopeClaims)
	set := make(map[string]struct{}, len(oidcScopes))
	for _, scope := range oidcScopes {
		set[scope] = struct{}{}
	}
	return set
}

// grantPermits reports whether the scopes a previously issued token was granted permit one being
// requested against them now, on a resource server using the given delimiter.
//
// A permission scope is permitted when the grant holds it, or holds one of its ancestors, so a
// client may ask for something beneath what it was granted rather than being refused for asking for
// less than it holds. Narrowing never works upwards, since a grant of a descendant does not confer
// the resource it sits under.
//
// An OIDC scope confers only itself. It is not a permission on any resource server, so it never
// stands as an ancestor, even where an application's scope-to-claims mapping names one that looks
// like a parent. An empty delimiter reduces the whole test to equality, which is what an unbound
// grant gets.
func grantPermits(requested string, granted []string, oidcGranted map[string]struct{}, delimiter string) bool {
	for _, grant := range granted {
		if grant == requested {
			return true
		}
		if _, isOIDC := oidcGranted[grant]; isOIDC {
			continue
		}
		if security.PermissionCovers(grant, requested, delimiter) {
			return true
		}
	}
	return false
}
