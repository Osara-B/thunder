// Copyright 2025 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package engine

import "context"

// AuthorizationEngine is the internal interface for authorization engines.
// This interface is NOT exported and is used internally by the authorization service.
// Different engines can be plugged in (RBAC, ABAC, ReBAC, Custom) by implementing this interface.
type AuthorizationEngine interface {
	// EvaluateAccess evaluates a single fine-grained access request.
	EvaluateAccess(
		ctx context.Context,
		request AccessEvaluationRequest,
	) (*AccessEvaluationResponse, error)

	// EvaluateAccessBatch evaluates multiple fine-grained access requests.
	EvaluateAccessBatch(
		ctx context.Context,
		request AccessEvaluationsRequest,
	) (*AccessEvaluationsResponse, error)
}

// Subject identifies the principal for an access evaluation. ID is optional: a subject with no
// local record is described by GroupIDs and RoleIDs alone.
type Subject struct {
	Category   string
	Type       string
	ID         string
	GroupIDs   []string
	RoleIDs    []string
	Properties map[string]interface{}
}

// ResourceServer identifies the resource server for an access evaluation.
type ResourceServer struct {
	ID         string
	Identifier string
	Engine     EngineConfig
	Properties map[string]interface{}
}

// EngineConfig identifies the configured authorization engine for a resource server.
type EngineConfig struct {
	Type       string
	Properties EngineProperties
}

// EngineProperties contains engine-specific resource-server settings.
type EngineProperties struct {
	PDPConnectionID string
}

// Permission identifies the permission string being evaluated.
type Permission struct {
	Name       string
	Properties map[string]interface{}
}

// AccessEvaluationRequest represents a single fine-grained access evaluation request.
type AccessEvaluationRequest struct {
	Subject        Subject
	ResourceServer ResourceServer
	Permission     Permission
	Context        map[string]interface{}
}

// AccessEvaluationResponse represents a single fine-grained access evaluation response.
type AccessEvaluationResponse struct {
	Decision bool
	Context  map[string]interface{}
	// GrantedInstead names the permissions the subject holds beneath a permission that was
	// refused. It accompanies a false decision and never changes it: holding what sits under a
	// resource is not holding the resource. Callers that mint a scope set use it; callers that
	// return the decision itself ignore it.
	//
	// Only the RBAC engine sets it. An external policy decision point has no view of the
	// permission tree.
	GrantedInstead []string
}

// AccessEvaluationsRequest represents a batched fine-grained access evaluation request.
type AccessEvaluationsRequest struct {
	Evaluations []AccessEvaluationRequest
}

// AccessEvaluationsResponse represents a batched fine-grained access evaluation response.
type AccessEvaluationsResponse struct {
	Evaluations []AccessEvaluationResponse
}
