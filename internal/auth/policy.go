package auth

import "context"

type Role string

const (
	Full     Role = "full"
	Readonly Role = "readonly"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Disabled bool   `json:"disabled"`
}

type Action string

// SharedWorkspaceID is an internal compatibility scope. It is not a user-facing environment.
const SharedWorkspaceID = "forge-shared-workspace"

const (
	View                Action = "view"
	Export              Action = "export"
	ManageOwnCredential Action = "manage_own_credential"
	Operate             Action = "operate"
	ManageUsers         Action = "manage_users"
)

// Provider authenticates a user with a provider-specific credential.
// Implementations must not retain the cleartext credential.
type Provider interface {
	Authenticate(context.Context, string) (User, error)
}

// Allowed applies the role check. Environment-scoped operations must additionally
// be checked against actual membership using the repository.
func Allowed(user User, action Action) bool {
	if user.Disabled || (user.Role != Full && user.Role != Readonly) {
		return false
	}
	switch action {
	case View, Export, ManageOwnCredential:
		return true
	case Operate, ManageUsers:
		return user.Role == Full
	default:
		return false
	}
}
