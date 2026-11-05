// Package simulation provides explicitly fake local fixtures.
package simulation

import (
	"context"
	"database/sql"
	"errors"
)

type Device struct {
	Name       string `json:"name"`
	BMCAddress string `json:"bmc_address"`
	Vendor     string `json:"vendor"`
	Selected   bool   `json:"selected"`
}

func Devices() []Device {
	return []Device{{"host1", "192.0.2.47", "Gigabyte", true}, {"host2", "192.0.2.48", "Lenovo", true}, {"host3", "192.0.2.49", "Yadro", false}}
}

// EnsureMode prevents an explicitly simulated instance from reusing a normal database.
func EnsureMode(ctx context.Context, db *sql.DB, enabled bool) error {
	want := "normal"
	if enabled {
		want = "simulation"
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var got string
	err = tx.QueryRowContext(ctx, `SELECT value FROM app_metadata WHERE key='runtime_mode'`).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		var existing int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&existing); err != nil {
			return err
		}
		if enabled && existing > 0 {
			return errors.New("cannot enable simulation on an existing unclassified database")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO app_metadata(key,value) VALUES('runtime_mode',?)`, want); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if got != want {
		return errors.New("database runtime mode does not match configuration")
	}
	return tx.Commit()
}
