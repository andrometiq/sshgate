package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

type policyQueryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func withPolicyImmediate[T any](ctx context.Context, database *sql.DB, action func(*sql.Tx) (T, error)) (T, error) {
	var zero T
	connection, err := database.Conn(ctx)
	if err != nil {
		return zero, fmt.Errorf("policy transaction: acquire connection: %w", err)
	}
	defer connection.Close()

	// Every database opened by sqlitestore uses _txlock=immediate, so BeginTx
	// obtains SQLite's write reservation before any read used by a CAS.
	transaction, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return zero, fmt.Errorf("policy transaction: begin immediate: %w", err)
	}
	defer transaction.Rollback()
	result, err := action(transaction)
	if err != nil {
		return zero, err
	}
	if err := transaction.Commit(); err != nil {
		return zero, fmt.Errorf("policy transaction: commit: %w", err)
	}
	return result, nil
}

func policyColumnNames(columns []policystore.Column) string {
	names := make([]string, len(columns))
	for index := range columns {
		names[index] = columns[index].Name
	}
	return strings.Join(names, ",")
}

func policyPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", count), ",")
}

func scanPolicyFields(scanner interface{ Scan(...any) error }, columns []policystore.Column) ([]policystore.Field, error) {
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := scanner.Scan(destinations...); err != nil {
		return nil, err
	}
	fields := make([]policystore.Field, len(columns))
	for index, value := range values {
		if value == nil {
			fields[index] = policystore.NullField()
			continue
		}
		switch columns[index].Kind {
		case policystore.ColumnText:
			switch typed := value.(type) {
			case string:
				fields[index] = policystore.TextField(typed)
			case []byte:
				fields[index] = policystore.TextField(string(typed))
			default:
				return nil, fmt.Errorf("scan policy column %s: TEXT has type %T", columns[index].Name, value)
			}
		case policystore.ColumnBlob:
			blob, ok := value.([]byte)
			if !ok {
				return nil, fmt.Errorf("scan policy column %s: BLOB has type %T", columns[index].Name, value)
			}
			fields[index] = policystore.BlobField(blob)
		case policystore.ColumnInteger:
			integer, ok := value.(int64)
			if !ok {
				return nil, fmt.Errorf("scan policy column %s: INTEGER has type %T", columns[index].Name, value)
			}
			fields[index] = policystore.IntegerField(integer)
		default:
			return nil, fmt.Errorf("scan policy column %s: unknown census kind", columns[index].Name)
		}
	}
	return fields, nil
}

func policyFieldValues(columns []policystore.Column, fields []policystore.Field) ([]any, error) {
	if len(columns) != len(fields) {
		return nil, fmt.Errorf("policy fields: %d columns and %d fields", len(columns), len(fields))
	}
	values := make([]any, len(fields))
	for index, field := range fields {
		if field.Null {
			values[index] = nil
			continue
		}
		switch columns[index].Kind {
		case policystore.ColumnText:
			text, err := field.Text()
			if err != nil {
				return nil, fmt.Errorf("policy field %s: %w", columns[index].Name, err)
			}
			values[index] = text
		case policystore.ColumnBlob:
			values[index] = field.Bytes()
		case policystore.ColumnInteger:
			integer, err := field.Integer()
			if err != nil {
				return nil, fmt.Errorf("policy field %s: %w", columns[index].Name, err)
			}
			values[index] = integer
		default:
			return nil, fmt.Errorf("policy field %s: unknown census kind", columns[index].Name)
		}
	}
	return values, nil
}

func loadPolicyRequest(ctx context.Context, queryer policyQueryer, key policystore.Key) (*policystore.Request, error) {
	row := queryer.QueryRowContext(ctx,
		"SELECT "+policyColumnNames(policystore.RequestColumns[:])+" FROM policy_requests WHERE principal=? AND request_id=?",
		key.Principal, key.RequestID)
	fields, err := scanPolicyFields(row, policystore.RequestColumns[:])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policystore.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load policy request: %w", err)
	}
	request, err := policystore.RequestFromFields(fields)
	if err != nil {
		return nil, fmt.Errorf("load policy request: %w", err)
	}
	return &request, nil
}

func loadPolicyVote(ctx context.Context, queryer policyQueryer, key policystore.Key, operator string) (*policystore.Vote, error) {
	row := queryer.QueryRowContext(ctx,
		"SELECT "+policyColumnNames(policystore.VoteColumns[:])+" FROM policy_votes WHERE principal=? AND request_id=? AND operator=?",
		key.Principal, key.RequestID, operator)
	fields, err := scanPolicyFields(row, policystore.VoteColumns[:])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policystore.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load policy vote: %w", err)
	}
	vote, err := policystore.VoteFromFields(fields)
	if err != nil {
		return nil, fmt.Errorf("load policy vote: %w", err)
	}
	return &vote, nil
}

func loadPolicyHead(ctx context.Context, queryer policyQueryer, authorityID, host string) (*policystore.Head, error) {
	row := queryer.QueryRowContext(ctx,
		"SELECT "+policyColumnNames(policystore.HeadColumns[:])+" FROM policy_heads WHERE authority_id=? AND host_key_fp=?",
		authorityID, host)
	fields, err := scanPolicyFields(row, policystore.HeadColumns[:])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policystore.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load policy head: %w", err)
	}
	head, err := policystore.HeadFromFields(fields)
	if err != nil {
		return nil, fmt.Errorf("load policy head: %w", err)
	}
	return &head, nil
}
