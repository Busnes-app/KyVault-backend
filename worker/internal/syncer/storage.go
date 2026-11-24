package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sync"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kyvault-worker/internal/vaultapi"
)

const (
	storageBatchMax   = 500
	storageBodyMax    = 64 << 10
	storageParallel   = 4
	storagePrepareMax = 500
)

var lowerUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ReportStorage exchanges the vault's prepared reports with KyIdentity and hands the
// grants back. The vault fixed each report's seq and bytes before returning it, so a
// failed exchange is resent unchanged next time (KyIdentity treats it as a replay).
//
// An org already in an exchange is skipped, so one org never has two reports in flight,
// while batches of unrelated orgs run in parallel.
func (s *Syncer) ReportStorage(ctx context.Context) error {
	reports, err := s.Vault.PrepareStorage(ctx, vaultapi.PrepareRequest{
		WantBytesDefault: s.StorageWantBytes,
		RenewBeforeSecs:  int64(s.StorageRenewBefore.Seconds()),
		Limit:            storagePrepareMax,
	})
	if err != nil {
		return err
	}
	var valid []suitedir.StorageReport
	for _, r := range reports {
		if !lowerUUID.MatchString(r.OrgID) || r.Seq <= 0 || r.UsedBytes < 0 || r.UsedBytes > 1<<53 || r.WantBytes < 0 || r.WantBytes > 1<<53 {
			s.log().Error("vault prepared an invalid storage report; skipped", "org_id", r.OrgID, "seq", r.Seq)
			continue
		}
		valid = append(valid, suitedir.StorageReport(r))
	}
	owned := s.acquire(valid)
	batches := chunkReports(owned)

	var wg sync.WaitGroup
	errs := make([]error, len(batches))
	sem := make(chan struct{}, storageParallel)
	for i, b := range batches {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { s.release(b); <-sem; wg.Done() }()
			errs[i] = s.exchange(ctx, b)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (s *Syncer) exchange(ctx context.Context, batch []suitedir.StorageReport) error {
	// Grant expiry runs from when the request left, never from when the answer arrived.
	sentAt := s.now().Unix()
	results, err := s.Directory.ReportStorage(ctx, batch)
	if err != nil {
		return err
	}
	sent := make(map[string]int64, len(batch))
	for _, r := range batch {
		sent[r.OrgID] = r.Seq
	}
	req := vaultapi.ApplyRequest{SentAt: sentAt, Results: make([]vaultapi.StorageResult, len(results))}
	for i, r := range results {
		out := vaultapi.StorageResult{OrgID: r.OrgID, Result: r.Result, ReportSeq: sent[r.OrgID]}
		if r.Result != "unknown_org" {
			out.Seq, out.CeilingBytes, out.TTLSeconds = &r.Seq, &r.CeilingBytes, &r.TTLSeconds
			out.PoolBytes, out.OrgUsedBytes, out.OverSince = &r.PoolBytes, &r.OrgUsedBytes, r.OverSince
		}
		req.Results[i] = out
	}
	res, err := s.Vault.ApplyStorage(ctx, req)
	if err != nil {
		return err
	}
	if len(res.StaleTenantIDs) > 0 {
		s.log().Error("STORAGE SEQUENCE STALE: KyIdentity holds a newer report sequence for these tenants. "+
			"Growth stays limited to the existing grant. An operator must run /internal/tenancy/v1/storage/repair-seq; "+
			"the worker never resets sequences.", "tenant_ids", res.StaleTenantIDs)
	}
	return nil
}

// acquire claims each org for this exchange and returns the reports it now owns.
func (s *Syncer) acquire(reports []suitedir.StorageReport) []suitedir.StorageReport {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]bool{}
	}
	var owned []suitedir.StorageReport
	for _, r := range reports {
		if s.inflight[r.OrgID] {
			continue
		}
		s.inflight[r.OrgID] = true
		owned = append(owned, r)
	}
	return owned
}

func (s *Syncer) release(reports []suitedir.StorageReport) {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	for _, r := range reports {
		delete(s.inflight, r.OrgID)
	}
}

// chunkReports splits reports into KyIdentity's limits: at most 500 per request and a
// {"reports":[...]} body of at most 64 KiB.
func chunkReports(reports []suitedir.StorageReport) [][]suitedir.StorageReport {
	const envelope = len(`{"reports":[]}`)
	var out [][]suitedir.StorageReport
	var cur []suitedir.StorageReport
	size := envelope
	for _, r := range reports {
		raw, _ := json.Marshal(r)
		n := len(raw)
		if len(cur) > 0 {
			n++ // comma
		}
		if len(cur) == storageBatchMax || size+n > storageBodyMax {
			out = append(out, cur)
			cur, size, n = nil, envelope, len(raw)
		}
		cur = append(cur, r)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
