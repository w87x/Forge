package profiles

import "testing"

func TestBMCPasswordRecipes(t *testing.T) {
	c := Connection{Driver: "redfish.generic", AddressSource: "explicit", Username: "admin", PasswordMode: "ipv4_octet"}
	for _, tc := range []struct {
		ip                   string
		width                int
		prefix, suffix, want string
		invalid              bool
	}{
		{"10.20.30.47", 0, "P", "S", "P47S", false}, {"10.20.30.47", 0, "", "S", "47S", false}, {"10.20.30.47", 0, "P", "", "P47", false},
		{"10.20.30.7", 3, "P", "S", "P007S", false}, {"10.20.30.0", 0, "", "", "0", false}, {"10.20.30.255", 0, "", "", "255", false},
		{"2001:db8::1", 0, "", "", "", true}, {"http://10.20.30.47", 0, "", "", "", true},
	} {
		c.PaddingWidth = tc.width
		got, err := Compose(c, tc.ip, "", nil, []byte(tc.prefix), []byte(tc.suffix))
		if tc.invalid {
			if err == nil {
				t.Errorf("%s accepted", tc.ip)
			}
			continue
		}
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: %q %v", tc.ip, got, err)
		}
	}
	c.PasswordMode = "serial_tail"
	c.SerialLast = 3
	c.SerialUpper = true
	got, err := Compose(c, "", "abcéxy", nil, []byte("P"), []byte("S"))
	if err != nil || string(got) != "PÉXYS" {
		t.Fatalf("serial: %q %v", got, err)
	}
	if _, err := Compose(c, "", "x", nil, nil, nil); err == nil {
		t.Fatal("short serial accepted")
	}
	c.PasswordMode = "static"
	c.StaticSecretID = "s"
	c.PrefixSecretID = ""
	c.SuffixSecretID = ""
	got, err = Compose(c, "", "", []byte("static"), nil, nil)
	if err != nil || string(got) != "static" {
		t.Fatalf("static: %q %v", got, err)
	}
}
