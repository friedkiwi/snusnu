package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type PrintJob struct {
	ID, OwnerID, SourceRouterID, SourceNetID, SourceCP, SourceLU string
	DeviceName, Title                                            string
	ByteCount, PageCount, CreatedAt                              int64
}

const printJobColumns = "id,owner_id,source_router_id,source_netid,source_cp,source_lu,device_name,title,byte_count,page_count,created_at"

func scanPrintJob(row interface{ Scan(...any) error }) (PrintJob, error) {
	var job PrintJob
	err := row.Scan(&job.ID, &job.OwnerID, &job.SourceRouterID, &job.SourceNetID, &job.SourceCP, &job.SourceLU, &job.DeviceName, &job.Title, &job.ByteCount, &job.PageCount, &job.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PrintJob{}, ErrNotFound
	}
	return job, err
}

func (s *Store) InsertPrintJob(ctx context.Context, job PrintJob) error {
	if job.ID == "" || job.OwnerID == "" || job.SourceRouterID == "" || job.SourceNetID == "" || job.SourceCP == "" || job.SourceLU == "" || job.DeviceName == "" || job.ByteCount <= 0 || job.PageCount <= 0 || job.CreatedAt <= 0 {
		return errors.New("invalid print job")
	}
	_, err := s.Exec(ctx, "INSERT INTO print_jobs ("+printJobColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?)", job.ID, job.OwnerID, job.SourceRouterID, job.SourceNetID, job.SourceCP, job.SourceLU, job.DeviceName, job.Title, job.ByteCount, job.PageCount, job.CreatedAt)
	return err
}

func (s *Store) PrintJobByID(ctx context.Context, ownerID, id string) (PrintJob, error) {
	return scanPrintJob(s.Row(ctx, "SELECT "+printJobColumns+" FROM print_jobs WHERE owner_id=? AND id=?", ownerID, id))
}

func (s *Store) ListPrintJobs(ctx context.Context, ownerID, search string, limit, offset int) ([]PrintJob, error) {
	if ownerID == "" || limit < 1 || limit > 100 || offset < 0 || offset > 1_000_000 {
		return nil, errors.New("invalid print job query")
	}
	search = strings.TrimSpace(search)
	if len(search) > 80 {
		return nil, errors.New("print search is too long")
	}
	pattern := "%" + strings.ToLower(search) + "%"
	query := "SELECT " + printJobColumns + " FROM print_jobs WHERE owner_id=? AND (LOWER(title) LIKE ? OR LOWER(source_netid||'.'||source_lu) LIKE ? OR LOWER(device_name) LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	rows, err := s.DB.QueryContext(ctx, s.Q(query), ownerID, pattern, pattern, pattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := make([]PrintJob, 0, limit)
	for rows.Next() {
		job, err := scanPrintJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}
