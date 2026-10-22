// Package visitor resolves per-API-key visitor identities and scores
// thumbmark uniqueness.
package visitor

import (
	"context"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/store"
)

// Repo is the subset of the store used to resolve visitors.
type Repo interface {
	GetVisitor(ctx context.Context, keyID, visitorID string) (*store.Visitor, error)
	FindVisitorByThumbmark(ctx context.Context, keyID, thumbmark string, since time.Time) (*store.Visitor, error)
	CreateVisitor(ctx context.Context, keyID, id string, now time.Time) (*store.Visitor, error)
	RecordVisit(ctx context.Context, keyID, visitorID, thumbmark string, now time.Time) (sharing, total int64, err error)
}

// Resolver maps requests to visitors.
type Resolver struct {
	Repo   Repo
	Window time.Duration // thumbmark match window
	Now    func() time.Time
	NewID  func() string
}

// Result is the outcome of resolving a visit.
type Result struct {
	ID                  string
	IsNew               bool
	FirstSeen, LastSeen time.Time
	Sharing, Total      int64
}

// Resolve identifies the visitor for keyID in spec order: a body visitorId that
// exists under this key, else a thumbmark match within Window, else a new
// visitor. A bodyVisitorID that is not a canonical (uppercase) ULID, or that
// belongs to another key, is ignored. The visit is then recorded.
func (r *Resolver) Resolve(ctx context.Context, keyID, bodyVisitorID, thumbmark string) (Result, error) {
	now := r.Now()
	var v *store.Visitor
	isNew := false

	if validULID(bodyVisitorID) {
		got, err := r.Repo.GetVisitor(ctx, keyID, bodyVisitorID)
		if err != nil {
			return Result{}, fmt.Errorf("get visitor: %w", err)
		}
		v = got
	}
	if v == nil {
		got, err := r.Repo.FindVisitorByThumbmark(ctx, keyID, thumbmark, now.Add(-r.Window))
		if err != nil {
			return Result{}, fmt.Errorf("find visitor by thumbmark: %w", err)
		}
		v = got
	}
	if v == nil {
		got, err := r.Repo.CreateVisitor(ctx, keyID, r.NewID(), now)
		if err != nil {
			return Result{}, fmt.Errorf("create visitor: %w", err)
		}
		v, isNew = got, true
	}

	sharing, total, err := r.Repo.RecordVisit(ctx, keyID, v.ID, thumbmark, now)
	if err != nil {
		return Result{}, fmt.Errorf("record visit: %w", err)
	}
	res := Result{ID: v.ID, IsNew: isNew, FirstSeen: v.FirstSeen, LastSeen: now, Sharing: sharing, Total: total}
	if after, err := r.Repo.GetVisitor(ctx, keyID, v.ID); err != nil {
		return Result{}, fmt.Errorf("reload visitor: %w", err)
	} else if after != nil {
		res.FirstSeen, res.LastSeen = after.FirstSeen, after.LastSeen
	}
	return res, nil
}

func validULID(s string) bool {
	id, err := ulid.ParseStrict(s)
	return err == nil && id.String() == s
}
