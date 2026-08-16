// Package policyarchive provides Linux held-descriptor maintenance leases and
// secure, content-addressed storage for hosted policy archive records.
//
// Canonical archive-record encoding remains owned by policystore. This package
// accepts and returns complete record bytes and never imports SQLite.
package policyarchive
