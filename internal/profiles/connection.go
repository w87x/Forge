// Package profiles contains typed, form-oriented profile data and resolution.
package profiles

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid profile")
var ErrConflict = errors.New("profile changed concurrently")
var ErrForbidden = errors.New("profile access denied")

type Connection struct {
	Driver         string `json:"driver"`
	Priority       int    `json:"priority"`
	AddressSource  string `json:"address_source"`
	AddressField   string `json:"address_field"`
	Username       string `json:"username"`
	Port           int    `json:"port"`
	PasswordMode   string `json:"password_mode"`
	StaticSecretID string `json:"static_secret_id"`
	PrefixSecretID string `json:"prefix_secret_id"`
	SuffixSecretID string `json:"suffix_secret_id"`
	PaddingWidth   int    `json:"padding_width"`
	SerialLast     int    `json:"serial_last"`
	SerialUpper    bool   `json:"serial_upper"`
}

func (c Connection) Validate() error {
	if c.Driver != "redfish.generic" || len(c.Username) == 0 || len(c.Username) > 128 || strings.ContainsAny(c.Username, "\x00\r\n") {
		return ErrInvalid
	}
	if c.AddressSource != "netbox_custom_field" && c.AddressSource != "explicit" {
		return ErrInvalid
	}
	if c.AddressSource == "netbox_custom_field" && (c.AddressField == "" || len(c.AddressField) > 128) {
		return ErrInvalid
	}
	if c.PaddingWidth < 0 || c.PaddingWidth > 3 {
		return ErrInvalid
	}
	if c.Port < 0 || c.Port > 65535 {
		return ErrInvalid
	}
	switch c.PasswordMode {
	case "static":
		if c.StaticSecretID == "" || c.PrefixSecretID != "" || c.SuffixSecretID != "" {
			return ErrInvalid
		}
	case "ipv4_octet":
		if c.StaticSecretID != "" {
			return ErrInvalid
		}
	case "serial_tail":
		if c.StaticSecretID != "" || c.SerialLast < 1 || c.SerialLast > 128 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// DeviceValue is safe to display; it never includes secret segments.
func (c Connection) DeviceValue(bmcIP, declaredSerial string) (string, error) {
	switch c.PasswordMode {
	case "static":
		return "", nil
	case "ipv4_octet":
		ip, err := netip.ParseAddr(bmcIP)
		if err != nil || !ip.Is4() {
			return "", ErrInvalid
		}
		octet := ip.As4()[3]
		value := strconv.Itoa(int(octet))
		if c.PaddingWidth > 0 {
			value = fmt.Sprintf("%0*d", c.PaddingWidth, int(octet))
		}
		return value, nil
	case "serial_tail":
		if !utf8.ValidString(declaredSerial) {
			return "", ErrInvalid
		}
		serial := []rune(strings.TrimSpace(declaredSerial))
		if c.SerialLast < 1 || len(serial) < c.SerialLast {
			return "", ErrInvalid
		}
		value := string(serial[len(serial)-c.SerialLast:])
		if c.SerialUpper {
			value = strings.ToUpper(value)
		}
		return value, nil
	default:
		return "", ErrInvalid
	}
}

func Compose(c Connection, bmcIP, declaredSerial string, static, prefix, suffix []byte) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.PasswordMode == "static" {
		if len(static) == 0 {
			return nil, ErrInvalid
		}
		return append([]byte(nil), static...), nil
	}
	value, err := c.DeviceValue(bmcIP, declaredSerial)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+len(value)+len(suffix))
	out = append(out, prefix...)
	out = append(out, value...)
	out = append(out, suffix...)
	return out, nil
}
