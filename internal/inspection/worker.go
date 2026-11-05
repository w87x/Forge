package inspection

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/redfish"
)

func (s *Service) Run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	const worker = "redfish-worker"
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Jobs.RecoverDue(ctx); err != nil && ctx.Err() == nil {
				logger.Error("recover jobs", "error", err)
			}
			if _, err := s.Jobs.ExpirePending(ctx); err != nil && ctx.Err() == nil {
				logger.Error("expire jobs", "error", err)
			}
			job, err := s.Jobs.ClaimKind(ctx, worker, 2*time.Minute, "redfish.inspect")
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("claim inspection", "error", err)
				}
				continue
			}
			if err = s.RunJob(ctx, job, worker); err != nil {
				message := "Inspection failed; check BMC reachability, TLS and credentials"
				if errors.Is(err, redfish.ErrAmbiguous) {
					message = "BMC exposes multiple systems; explicit selection is not yet supported"
				} else if errors.Is(err, redfish.ErrNotAllowed) {
					message = "BMC address is not in an allowed network"
				} else if errors.Is(err, inventory.ErrStale) {
					message = "Inventory, credentials or profile inputs changed; create a new inspection"
				} else if errors.Is(err, ErrUnsupported) {
					message = "Connection profile address source is not yet supported"
				} else if errors.Is(err, ErrForbidden) {
					message = "Inspection owner no longer has permission"
				}
				if parkErr := s.Jobs.Park(ctx, job.ID, worker, job.Generation, message); parkErr != nil && !errors.Is(parkErr, jobs.ErrConflict) && ctx.Err() == nil {
					logger.Error("park inspection", "job_id", job.ID, "error", parkErr)
				}
				continue
			}
			if err = s.Jobs.Complete(ctx, job.ID, worker, job.Generation); err != nil && !errors.Is(err, jobs.ErrConflict) && ctx.Err() == nil {
				logger.Error("complete inspection", "job_id", job.ID, "error", err)
			}
		}
	}
}
