package registration

import (
	"context"
	"fmt"
)

// Validator handles registration token validation.
type Validator struct {
	store Store
}

// NewValidator creates a new token validator.
func NewValidator(store Store) *Validator {
	return &Validator{
		store: store,
	}
}

// ValidateToken validates a registration token and returns tenant information.
func (v *Validator) ValidateToken(ctx context.Context, req *TokenValidationRequest) (*TokenValidationResponse, error) {
	// Retrieve token from store
	token, err := v.store.GetToken(ctx, req.Token)
	if err != nil {
		return &TokenValidationResponse{
			Valid:  false,
			Reason: "token not found",
		}, nil
	}

	// Check if token is valid
	if !token.IsValid() {
		reason := "token invalid"
		if token.Revoked {
			reason = "token revoked"
		} else if token.ExpiresAt != nil {
			reason = "token expired"
		} else if token.SingleUse && token.UsedAt != nil {
			reason = "token already used"
		}

		return &TokenValidationResponse{
			Valid:  false,
			Reason: reason,
		}, nil
	}

	// Mark token as used
	token.MarkUsed(req.StewardID)
	if err := v.store.UpdateToken(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to update token: %w", err)
	}

	// Return valid response with tenant info
	return &TokenValidationResponse{
		Valid:         true,
		TenantID:      token.TenantID,
		ControllerURL: token.ControllerURL,
		Group:         token.Group,
	}, nil
}

// RevokeToken revokes a registration token.
func (v *Validator) RevokeToken(ctx context.Context, tokenStr string) error {
	token, err := v.store.GetToken(ctx, tokenStr)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	token.Revoke()
	if err := v.store.UpdateToken(ctx, token); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}
