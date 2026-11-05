package auth

import "testing"

func TestRoles(t *testing.T) {
	for _, tc := range []struct {
		user   User
		action Action
		want   bool
	}{
		{User{Role: Full}, Operate, true}, {User{Role: Readonly}, Operate, false},
		{User{Role: Readonly}, View, true}, {User{Role: Readonly}, ManageOwnCredential, true},
		{User{Role: Full, Disabled: true}, View, false}, {User{Role: "admin"}, Operate, false},
		{User{Role: Full}, "unknown", false},
	} {
		if got := Allowed(tc.user, tc.action); got != tc.want {
			t.Errorf("%+v %s = %v", tc.user, tc.action, got)
		}
	}
}
