package simulation

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"forge/internal/auth"
	"forge/internal/jobs"
)

// Run executes only the non-operational simulation job kind. It never connects
// to NetBox, a BMC, or a server.
func Run(ctx context.Context, store *jobs.Store, logger *slog.Logger) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	const worker = "simulation-worker"
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.RecoverDue(ctx); err != nil && ctx.Err() == nil {
				logger.Error("recover jobs", "error", err)
			}
			if _, err := store.ExpirePending(ctx); err != nil && ctx.Err() == nil {
				logger.Error("expire jobs", "error", err)
			}
			job, err := store.ClaimKind(ctx, worker, 5*time.Second, "simulation.inspect")
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("claim simulation job", "error", err)
				}
				continue
			}
			var actor auth.User
			err = store.DB.QueryRowContext(ctx, `SELECT id,username,role,disabled FROM users WHERE id=?`, job.ActorID).Scan(&actor.ID, &actor.Username, &actor.Role, &actor.Disabled)
			if err != nil || !auth.Allowed(actor, auth.Operate) {
				if parkErr := store.Park(ctx, job.ID, worker, job.Generation, "Job owner no longer has permission"); parkErr != nil && ctx.Err() == nil {
					logger.Error("park simulation job", "job_id", job.ID, "error", parkErr)
				}
				continue
			}
			for i := 0; i < 2; i++ {
				if err = store.CompleteLocalStep(ctx, job.ID, worker, job.Generation, i); err != nil {
					break
				}
			}
			if err == nil {
				err = store.Complete(ctx, job.ID, worker, job.Generation)
			}
			if err != nil && !errors.Is(err, jobs.ErrConflict) && ctx.Err() == nil {
				logger.Error("run simulation job", "job_id", job.ID, "error", err)
			}
		}
	}
}
