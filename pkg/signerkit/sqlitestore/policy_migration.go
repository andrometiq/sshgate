package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// policyMigration6SQL is intentionally explicit. Column order is part of the
// logical-accounting and archive-record ABIs, so the schema verifier below
// treats the four policy table censuses as frozen data rather than relying on
// struct or map iteration.
const policyMigration6SQL = `
CREATE TABLE IF NOT EXISTS policy_authority_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  authority_id TEXT NOT NULL UNIQUE CHECK (
    length(authority_id) = 38 AND substr(authority_id,1,6) = 'pauth_' AND
    substr(authority_id,7) NOT GLOB '*[^0-9a-f]*'
  ),
  accounting_version TEXT NOT NULL CHECK (accounting_version = 'sshgate-policy-logical-bytes-v3'),
  archive_id TEXT NOT NULL CHECK (
    length(archive_id) = 38 AND substr(archive_id,1,6) = 'parch_' AND
    substr(archive_id,7) NOT GLOB '*[^0-9a-f]*'
  ),
  max_heads INTEGER NOT NULL CHECK (max_heads = 256),
  max_requests INTEGER NOT NULL CHECK (max_requests = 1024),
  max_logical_bytes INTEGER NOT NULL CHECK (max_logical_bytes = 268435456),
  max_active_global INTEGER NOT NULL CHECK (max_active_global = 256),
  max_active_per_principal INTEGER NOT NULL CHECK (max_active_per_principal = 64),
  max_votes_per_request INTEGER NOT NULL CHECK (max_votes_per_request = 256),
  max_rejection_reserved_bytes_per_principal INTEGER NOT NULL CHECK (
    max_rejection_reserved_bytes_per_principal > 0 AND
    max_rejection_reserved_bytes_per_principal <= 8388608
  ),
  config_digest TEXT NOT NULL CHECK (
    length(config_digest) = 64 AND config_digest NOT GLOB '*[^0-9a-f]*'
  ),
  requester_operator_id TEXT NOT NULL CHECK (
    requester_operator_id <> '' AND
    length(CAST(requester_operator_id AS BLOB)) <= 128 AND
    instr(CAST(requester_operator_id AS BLOB), x'00') = 0 AND
    policy_valid_identity(requester_operator_id) = 1
  ),
  required_approvals INTEGER NOT NULL CHECK (required_approvals > 0 AND required_approvals <= 256),
  deny_veto INTEGER NOT NULL CHECK (deny_veto IN (0,1)),
  allow_self_approve INTEGER NOT NULL CHECK (allow_self_approve IN (0,1)),
  policy_voter_role TEXT NOT NULL CHECK (policy_voter_role <> ''),
  voter_eligibility_version TEXT NOT NULL CHECK (voter_eligibility_version <> ''),
  vote_step_up_required INTEGER NOT NULL CHECK (vote_step_up_required IN (0,1)),
  vote_auth_methods_json TEXT NOT NULL CHECK (
    (vote_step_up_required = 0 AND vote_auth_methods_json = '["session"]') OR
    (vote_step_up_required = 1 AND vote_auth_methods_json = '["totp"]')
  ),
  review_renderer_version TEXT NOT NULL CHECK (review_renderer_version = 'sshgate-policy-review-v2'),
  review_rules_digest TEXT NOT NULL CHECK (
    length(review_rules_digest) = 64 AND review_rules_digest NOT GLOB '*[^0-9a-f]*'
  ),
  logical_used_bytes INTEGER NOT NULL CHECK (logical_used_bytes >= 0),
  logical_reserved_bytes INTEGER NOT NULL CHECK (logical_reserved_bytes >= 0),
  full_request_count INTEGER NOT NULL CHECK (full_request_count >= 0 AND full_request_count <= 1024),
  head_count INTEGER NOT NULL CHECK (head_count >= 0 AND head_count <= 256),
  active_count INTEGER NOT NULL CHECK (active_count >= 0 AND active_count <= 256),
  created_at INTEGER NOT NULL,
  UNIQUE (singleton, authority_id),
  CHECK (logical_used_bytes + logical_reserved_bytes <= max_logical_bytes)
);

CREATE TABLE IF NOT EXISTS policy_authority_key_bindings (
  signer_key_id TEXT PRIMARY KEY CHECK (
    length(signer_key_id) = 64 AND signer_key_id NOT GLOB '*[^0-9a-f]*'
  ),
  signer_public_key BLOB NOT NULL UNIQUE CHECK (length(signer_public_key) = 32),
  authority_id TEXT NOT NULL CHECK (
    length(authority_id) = 38 AND substr(authority_id,1,6) = 'pauth_' AND
    substr(authority_id,7) NOT GLOB '*[^0-9a-f]*'
  ),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_requests (
  principal TEXT NOT NULL CHECK (
    principal <> '' AND length(CAST(principal AS BLOB)) <= 128 AND
    instr(CAST(principal AS BLOB), x'00') = 0 AND policy_valid_identity(principal) = 1
  ),
  request_id TEXT NOT NULL CHECK (
    length(request_id) = 35 AND substr(request_id,1,3) = 'pm_' AND
    substr(request_id,4) NOT GLOB '*[^0-9a-f]*'
  ),
  review_id TEXT NOT NULL UNIQUE CHECK (
    length(review_id) = 35 AND substr(review_id,1,3) = 'pr_' AND
    substr(review_id,4) NOT GLOB '*[^0-9a-f]*'
  ),
  authority_singleton INTEGER NOT NULL DEFAULT 1 CHECK (authority_singleton = 1),
  authority_id TEXT NOT NULL CHECK (
    length(authority_id) = 38 AND substr(authority_id,1,6) = 'pauth_' AND
    substr(authority_id,7) NOT GLOB '*[^0-9a-f]*'
  ),
  storage_kind TEXT NOT NULL CHECK (storage_kind IN ('full','tombstone')),
  purpose TEXT NOT NULL CHECK (purpose = 'base_manifest_sign_v1'),
  canonical_request BLOB,
  payload BLOB,
  tuple_digest TEXT NOT NULL CHECK (length(tuple_digest) = 64 AND tuple_digest NOT GLOB '*[^0-9a-f]*'),
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  base_digest TEXT NOT NULL CHECK (length(base_digest) = 64 AND base_digest NOT GLOB '*[^0-9a-f]*'),
  host_key_fp TEXT NOT NULL CHECK (host_key_fp <> ''),
  expected_head_digest TEXT NOT NULL CHECK (
    expected_head_digest = '' OR
    (length(expected_head_digest) = 64 AND expected_head_digest NOT GLOB '*[^0-9a-f]*')
  ),
  expected_signer_key_id TEXT NOT NULL CHECK (
    length(expected_signer_key_id) = 64 AND expected_signer_key_id NOT GLOB '*[^0-9a-f]*'
  ),
  bootstrap INTEGER NOT NULL CHECK (bootstrap IN (0,1)),
  trusted_head_envelope BLOB,
  trusted_head_digest TEXT,
  trusted_head_key_id TEXT,
  trusted_head_public_key BLOB,
  trusted_head_epoch_be BLOB CHECK (trusted_head_epoch_be IS NULL OR length(trusted_head_epoch_be) = 8),
  trusted_head_revision_be BLOB CHECK (trusted_head_revision_be IS NULL OR length(trusted_head_revision_be) = 8),
  trusted_head_row_version INTEGER,
  claimed_head_envelope BLOB,
  claimed_head_digest TEXT,
  claimed_head_key_id TEXT,
  claimed_head_public_key BLOB,
  claimed_head_epoch_be BLOB CHECK (claimed_head_epoch_be IS NULL OR length(claimed_head_epoch_be) = 8),
  claimed_head_revision_be BLOB CHECK (claimed_head_revision_be IS NULL OR length(claimed_head_revision_be) = 8),
  claimed_head_row_version INTEGER,
  frozen_signer_key_id TEXT,
  frozen_signer_public_key BLOB,
  epoch_be BLOB NOT NULL CHECK (length(epoch_be) = 8 AND epoch_be <> x'0000000000000000'),
  revision_be BLOB NOT NULL CHECK (length(revision_be) = 8 AND revision_be <> x'0000000000000000'),
  miss_action TEXT NOT NULL CHECK (miss_action IN ('classifier','ask','deny')),
  growth TEXT NOT NULL CHECK (
    growth IN ('none','sign-to-add','out-of-band') AND
    (miss_action <> 'classifier' OR growth = 'none') AND
    (growth <> 'sign-to-add' OR miss_action = 'ask')
  ),
  entry_count INTEGER NOT NULL CHECK (entry_count >= 0 AND entry_count <= 256),
  revocation_count INTEGER NOT NULL CHECK (revocation_count >= 0 AND revocation_count <= 4096),
  logical_change_count INTEGER NOT NULL CHECK (logical_change_count >= 0),
  review_json BLOB,
  review_sha256 TEXT,
  review_rendered_bytes INTEGER,
  review_item_count INTEGER,
  review_renderer_version TEXT,
  review_rules_digest TEXT,
  eligible_voters_json BLOB,
  eligible_voters_sha256 TEXT,
  eligible_voter_count INTEGER,
  vote_step_up_required INTEGER NOT NULL CHECK (vote_step_up_required IN (0,1)),
  vote_auth_methods_json BLOB NOT NULL CHECK (
    (vote_step_up_required = 0 AND CAST(vote_auth_methods_json AS TEXT) = '["session"]') OR
    (vote_step_up_required = 1 AND CAST(vote_auth_methods_json AS TEXT) = '["totp"]')
  ),
  vote_auth_methods_sha256 TEXT NOT NULL CHECK (
    length(vote_auth_methods_sha256) = 64 AND vote_auth_methods_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  required_approvals INTEGER NOT NULL CHECK (required_approvals > 0 AND required_approvals <= 256),
  deny_veto INTEGER NOT NULL CHECK (deny_veto IN (0,1)),
  allow_self_approve INTEGER NOT NULL CHECK (allow_self_approve IN (0,1)),
  requester_principal TEXT NOT NULL CHECK (
    requester_principal <> '' AND length(CAST(requester_principal AS BLOB)) <= 128 AND
    instr(CAST(requester_principal AS BLOB), x'00') = 0 AND
    policy_valid_identity(requester_principal) = 1
  ),
  state TEXT NOT NULL CHECK (state IN (
    'received_unaudited','rejection_unaudited','rejection_error_received','pending',
    'approved_materializing','approved_unexposed','no_op_unexposed','denial_received',
    'error_received','approved','denied','error'
  )),
  state_version INTEGER NOT NULL CHECK (state_version > 0),
  submission_audited INTEGER NOT NULL DEFAULT 0 CHECK (submission_audited IN (0,1)),
  pre_mint_audited INTEGER NOT NULL DEFAULT 0 CHECK (pre_mint_audited IN (0,1)),
  result_audited INTEGER NOT NULL DEFAULT 0 CHECK (result_audited IN (0,1)),
  terminal_audited INTEGER NOT NULL DEFAULT 0 CHECK (terminal_audited IN (0,1)),
  no_op INTEGER NOT NULL DEFAULT 0 CHECK (no_op IN (0,1)),
  error_family TEXT NOT NULL DEFAULT '' CHECK (
    error_family IN ('','semantic-rejection','processing-error','publication-error')
  ),
  failure_code TEXT NOT NULL DEFAULT '',
  result_envelope BLOB,
  result_sha256 TEXT NOT NULL DEFAULT '' CHECK (
    result_sha256 = '' OR
    (length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*')
  ),
  pending_response BLOB,
  terminal_response BLOB,
  terminal_http_status INTEGER,
  reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
  recovery_lease_owner TEXT NOT NULL DEFAULT '',
  recovery_lease_until INTEGER NOT NULL DEFAULT 0,
  recovery_lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (recovery_lease_generation >= 0),
  archive_id TEXT,
  archive_object_sha256 TEXT,
  archive_record_bytes INTEGER,
  terminal_response_sha256 TEXT,
  terminal_response_bytes INTEGER,
  compaction_delete_guard INTEGER NOT NULL DEFAULT 0 CHECK (compaction_delete_guard IN (0,1)),
  logical_bytes INTEGER NOT NULL CHECK (logical_bytes > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resolved_at INTEGER,
  PRIMARY KEY (principal, request_id),
  FOREIGN KEY (authority_singleton, authority_id)
    REFERENCES policy_authority_meta(singleton, authority_id),

  CONSTRAINT policy_request_pair_checks CHECK (
    ((storage_kind = 'full' AND
      ((result_envelope IS NULL AND result_sha256 = '') OR
       (result_envelope IS NOT NULL AND length(result_sha256) = 64 AND
        result_sha256 NOT GLOB '*[^0-9a-f]*'))) OR
     (storage_kind = 'tombstone' AND result_envelope IS NULL AND
      (result_sha256 = '' OR
       (length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*')))) AND
    ((recovery_lease_owner = '' AND recovery_lease_until = 0) OR
     (recovery_lease_owner <> '' AND recovery_lease_until > 0 AND recovery_lease_generation > 0)) AND
    ((review_json IS NULL AND review_sha256 IS NULL AND review_rendered_bytes IS NULL AND
      review_item_count IS NULL AND review_renderer_version IS NULL AND review_rules_digest IS NULL) OR
     (review_json IS NOT NULL AND length(review_sha256) = 64 AND review_sha256 NOT GLOB '*[^0-9a-f]*' AND
      review_rendered_bytes >= 0 AND review_rendered_bytes <= 131072 AND
      review_item_count >= 0 AND review_item_count <= 40 AND
      review_renderer_version = 'sshgate-policy-review-v2' AND
      length(review_rules_digest) = 64 AND review_rules_digest NOT GLOB '*[^0-9a-f]*')) AND
    ((eligible_voters_json IS NULL AND eligible_voters_sha256 IS NULL AND eligible_voter_count IS NULL) OR
     (eligible_voters_json IS NOT NULL AND length(eligible_voters_sha256) = 64 AND
      eligible_voters_sha256 NOT GLOB '*[^0-9a-f]*' AND
      eligible_voter_count >= 0 AND eligible_voter_count <= 256)) AND
    ((frozen_signer_key_id IS NULL AND frozen_signer_public_key IS NULL) OR
     (length(frozen_signer_key_id) = 64 AND frozen_signer_key_id NOT GLOB '*[^0-9a-f]*' AND
      length(frozen_signer_public_key) = 32)) AND
    ((trusted_head_envelope IS NULL AND trusted_head_digest IS NULL AND trusted_head_key_id IS NULL AND
      trusted_head_public_key IS NULL AND trusted_head_epoch_be IS NULL AND
      trusted_head_revision_be IS NULL AND trusted_head_row_version IS NULL) OR
     (trusted_head_envelope IS NOT NULL AND length(trusted_head_digest) = 64 AND
      trusted_head_digest NOT GLOB '*[^0-9a-f]*' AND length(trusted_head_key_id) = 64 AND
      trusted_head_key_id NOT GLOB '*[^0-9a-f]*' AND length(trusted_head_public_key) = 32 AND
      length(trusted_head_epoch_be) = 8 AND trusted_head_epoch_be <> x'0000000000000000' AND
      length(trusted_head_revision_be) = 8 AND trusted_head_revision_be <> x'0000000000000000' AND
      trusted_head_row_version > 0)) AND
    ((claimed_head_envelope IS NULL AND claimed_head_digest IS NULL AND claimed_head_key_id IS NULL AND
      claimed_head_public_key IS NULL AND claimed_head_epoch_be IS NULL AND
      claimed_head_revision_be IS NULL AND claimed_head_row_version IS NULL) OR
     (claimed_head_envelope IS NOT NULL AND length(claimed_head_digest) = 64 AND
      claimed_head_digest NOT GLOB '*[^0-9a-f]*' AND length(claimed_head_key_id) = 64 AND
      claimed_head_key_id NOT GLOB '*[^0-9a-f]*' AND length(claimed_head_public_key) = 32 AND
      length(claimed_head_epoch_be) = 8 AND claimed_head_epoch_be <> x'0000000000000000' AND
      length(claimed_head_revision_be) = 8 AND claimed_head_revision_be <> x'0000000000000000' AND
      claimed_head_row_version > 0))
  ),

  CONSTRAINT policy_request_matrix_1 CHECK (
    storage_kind <> 'full' OR
    (error_family = 'semantic-rejection' AND failure_code IN (
      'invalid_policy_request','policy_request_in_progress','signer_key_changed',
      'stale_policy_head','policy_key_transition_required'
    )) OR
    (canonical_request IS NOT NULL AND payload IS NOT NULL AND review_json IS NOT NULL AND
     eligible_voters_json IS NOT NULL AND frozen_signer_key_id = expected_signer_key_id AND
     length(frozen_signer_public_key) = 32 AND pending_response IS NOT NULL AND
     archive_id IS NULL AND archive_object_sha256 IS NULL AND archive_record_bytes IS NULL AND
     terminal_response_sha256 IS NULL AND terminal_response_bytes IS NULL)
  ),

  CONSTRAINT policy_request_matrix_2a CHECK (
    storage_kind <> 'full' OR
    NOT (error_family = 'semantic-rejection' AND failure_code IN (
      'invalid_policy_request','policy_request_in_progress','signer_key_changed',
      'stale_policy_head','policy_key_transition_required'
    )) OR
    (state IN ('rejection_unaudited','rejection_error_received','error') AND
     canonical_request IS NOT NULL AND payload IS NOT NULL AND
     claimed_head_envelope IS NULL AND claimed_head_digest IS NULL AND claimed_head_key_id IS NULL AND
     claimed_head_public_key IS NULL AND claimed_head_epoch_be IS NULL AND
     claimed_head_revision_be IS NULL AND claimed_head_row_version IS NULL AND
     result_envelope IS NULL AND result_sha256 = '' AND pending_response IS NULL AND no_op = 0 AND
     pre_mint_audited = 0 AND result_audited = 0 AND
     archive_id IS NULL AND archive_object_sha256 IS NULL AND archive_record_bytes IS NULL AND
     terminal_response_sha256 IS NULL AND terminal_response_bytes IS NULL AND
     reserved_bytes >= length(canonical_request) + length(payload) AND
     (state <> 'error' OR reserved_bytes = length(canonical_request) + length(payload)))
  ),

  CONSTRAINT policy_request_matrix_2b CHECK (
    NOT (error_family = 'semantic-rejection' AND failure_code = 'quorum_unattainable') OR
    (storage_kind IN ('full','tombstone') AND state IN ('error_received','error') AND
     submission_audited = 1 AND result_envelope IS NULL AND result_sha256 = '' AND
     (storage_kind = 'tombstone' OR pending_response IS NOT NULL))
  ),

  CONSTRAINT policy_request_matrix_3 CHECK (
    storage_kind <> 'full' OR
    (error_family = 'semantic-rejection' AND failure_code IN (
      'invalid_policy_request','policy_request_in_progress','signer_key_changed',
      'stale_policy_head','policy_key_transition_required'
    )) OR bootstrap = 0 OR
    (expected_head_digest = '' AND trusted_head_envelope IS NULL AND trusted_head_digest IS NULL AND
     trusted_head_key_id IS NULL AND trusted_head_public_key IS NULL AND trusted_head_epoch_be IS NULL AND
     trusted_head_revision_be IS NULL AND trusted_head_row_version IS NULL AND
     claimed_head_envelope IS NULL AND claimed_head_digest IS NULL AND claimed_head_key_id IS NULL AND
     claimed_head_public_key IS NULL AND claimed_head_epoch_be IS NULL AND
     claimed_head_revision_be IS NULL AND claimed_head_row_version IS NULL)
  ),

  CONSTRAINT policy_request_matrix_4 CHECK (
    storage_kind <> 'full' OR
    (error_family = 'semantic-rejection' AND failure_code IN (
      'invalid_policy_request','policy_request_in_progress','signer_key_changed',
      'stale_policy_head','policy_key_transition_required'
    )) OR bootstrap = 1 OR
    (length(expected_head_digest) = 64 AND expected_head_digest NOT GLOB '*[^0-9a-f]*' AND
     trusted_head_envelope IS NOT NULL AND
     (state IN ('error_received','error') OR
      ((state IN ('approved_materializing','approved_unexposed') OR
        (state = 'approved' AND no_op = 0)) = (claimed_head_envelope IS NOT NULL))) AND
     (claimed_head_envelope IS NULL OR recovery_lease_generation > 0))
  ),

  CONSTRAINT policy_request_matrix_5 CHECK (
    storage_kind <> 'tombstone' OR
    (state IN ('approved','denied','error') AND terminal_http_status IS NOT NULL AND resolved_at IS NOT NULL AND
     canonical_request IS NULL AND payload IS NULL AND
     trusted_head_envelope IS NULL AND trusted_head_digest IS NULL AND trusted_head_key_id IS NULL AND
     trusted_head_public_key IS NULL AND trusted_head_epoch_be IS NULL AND
     trusted_head_revision_be IS NULL AND trusted_head_row_version IS NULL AND
     claimed_head_envelope IS NULL AND claimed_head_digest IS NULL AND claimed_head_key_id IS NULL AND
     claimed_head_public_key IS NULL AND claimed_head_epoch_be IS NULL AND
     claimed_head_revision_be IS NULL AND claimed_head_row_version IS NULL AND
     frozen_signer_key_id IS NULL AND frozen_signer_public_key IS NULL AND
     review_json IS NULL AND review_sha256 IS NULL AND review_rendered_bytes IS NULL AND
     review_item_count IS NULL AND review_renderer_version IS NULL AND review_rules_digest IS NULL AND
     eligible_voters_json IS NULL AND eligible_voters_sha256 IS NULL AND eligible_voter_count IS NULL AND
     result_envelope IS NULL AND pending_response IS NULL AND terminal_response IS NULL AND
     length(archive_id) = 38 AND substr(archive_id,1,6) = 'parch_' AND
     substr(archive_id,7) NOT GLOB '*[^0-9a-f]*' AND
     length(archive_object_sha256) = 64 AND archive_object_sha256 NOT GLOB '*[^0-9a-f]*' AND
     archive_record_bytes > 0 AND length(terminal_response_sha256) = 64 AND
     terminal_response_sha256 NOT GLOB '*[^0-9a-f]*' AND terminal_response_bytes > 0 AND
     ((error_family = 'semantic-rejection' AND failure_code IN (
       'invalid_policy_request','policy_request_in_progress','signer_key_changed',
       'stale_policy_head','policy_key_transition_required'
      ) AND reserved_bytes > 0) OR
      (NOT (error_family = 'semantic-rejection' AND failure_code IN (
       'invalid_policy_request','policy_request_in_progress','signer_key_changed',
       'stale_policy_head','policy_key_transition_required'
      )) AND reserved_bytes = 0)))
  ),

  CONSTRAINT policy_request_lifecycle CHECK (
    ((state IN ('approved','denied','error') AND storage_kind = 'full' AND
      terminal_response IS NOT NULL AND terminal_http_status IS NOT NULL AND resolved_at IS NOT NULL) OR
     (state NOT IN ('approved','denied','error') AND terminal_response IS NULL AND
      terminal_http_status IS NULL AND resolved_at IS NULL) OR storage_kind = 'tombstone') AND
    (state NOT IN ('approved','denied','error') OR reserved_bytes = 0 OR
     (error_family = 'semantic-rejection' AND failure_code IN (
       'invalid_policy_request','policy_request_in_progress','signer_key_changed',
       'stale_policy_head','policy_key_transition_required'))) AND
    ((state IN ('received_unaudited','pending','approved_materializing','approved_unexposed',
                'no_op_unexposed','denial_received','approved','denied') AND
       error_family = '' AND failure_code = '') OR
     (state IN ('rejection_unaudited','rejection_error_received','error_received','error') AND
       error_family <> '' AND failure_code <> '')) AND
    ((error_family = 'semantic-rejection' AND failure_code IN (
       'invalid_policy_request','policy_request_in_progress','signer_key_changed',
       'stale_policy_head','policy_key_transition_required','quorum_unattainable')) OR
     (error_family = 'processing-error' AND failure_code IN (
       'signer_key_changed','stale_policy_head','policy_materialization_failed')) OR
     (error_family = 'publication-error' AND failure_code IN ('signer_key_changed','stale_policy_head')) OR
     (error_family = '' AND failure_code = '')) AND
    (state IN ('received_unaudited','rejection_unaudited') OR submission_audited = 1) AND
    (state <> 'approved_materializing' OR (result_envelope IS NULL AND result_audited = 0)) AND
    (state <> 'approved_unexposed' OR (result_envelope IS NOT NULL AND pre_mint_audited = 1)) AND
    (state <> 'no_op_unexposed' OR (no_op = 1 AND result_envelope IS NOT NULL)) AND
    (state <> 'pending' OR (no_op = 0 AND result_envelope IS NULL AND pre_mint_audited = 0 AND
                            result_audited = 0 AND terminal_audited = 0)) AND
    (state <> 'denial_received' OR (no_op = 0 AND result_envelope IS NULL)) AND
    (error_family <> 'publication-error' OR
      (((storage_kind = 'full' AND result_envelope IS NOT NULL) OR
        (storage_kind = 'tombstone' AND result_sha256 <> '')) AND
       ((no_op = 0 AND result_audited = 1) OR (no_op = 1 AND terminal_audited = 1)))) AND
    (state <> 'approved' OR
      (terminal_http_status = 200 AND result_sha256 <> '' AND ((no_op = 1 AND terminal_audited = 1) OR
                               (no_op = 0 AND pre_mint_audited = 1 AND result_audited = 1)))) AND
    (state <> 'denied' OR
      (terminal_http_status = 200 AND no_op = 0 AND result_envelope IS NULL AND terminal_audited = 1)) AND
    (state <> 'error' OR
      (terminal_audited = 1 AND
       ((failure_code = 'invalid_policy_request' AND terminal_http_status = 400) OR
        (failure_code = 'policy_materialization_failed' AND terminal_http_status = 500) OR
        (failure_code IN ('policy_request_in_progress','signer_key_changed','stale_policy_head',
                          'policy_key_transition_required','quorum_unattainable') AND terminal_http_status = 409))))
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS policy_one_active_host
  ON policy_requests(authority_id, host_key_fp)
  WHERE storage_kind = 'full' AND state IN (
    'received_unaudited','pending','approved_materializing',
    'approved_unexposed','no_op_unexposed','denial_received','error_received'
  );
CREATE INDEX IF NOT EXISTS policy_pending_created
  ON policy_requests(state, created_at);
CREATE INDEX IF NOT EXISTS policy_rejection_budget
  ON policy_requests(principal, error_family, failure_code, storage_kind, created_at, reserved_bytes);

CREATE TABLE IF NOT EXISTS policy_votes (
  principal TEXT NOT NULL CHECK (
    principal <> '' AND length(CAST(principal AS BLOB)) <= 128 AND
    instr(CAST(principal AS BLOB), x'00') = 0 AND policy_valid_identity(principal) = 1
  ),
  request_id TEXT NOT NULL CHECK (
    length(request_id) = 35 AND substr(request_id,1,3) = 'pm_' AND
    substr(request_id,4) NOT GLOB '*[^0-9a-f]*'
  ),
  operator TEXT NOT NULL CHECK (
    operator <> '' AND length(CAST(operator AS BLOB)) <= 128 AND
    instr(CAST(operator AS BLOB), x'00') = 0 AND policy_valid_identity(operator) = 1
  ),
  decision TEXT NOT NULL CHECK (decision IN ('approve','deny')),
  authn_method TEXT NOT NULL CHECK (authn_method IN ('session','totp')),
  ts INTEGER NOT NULL,
  audited INTEGER NOT NULL DEFAULT 0 CHECK (audited IN (0,1)),
  audit_state_version INTEGER NOT NULL CHECK (audit_state_version > 0),
  tuple_digest TEXT NOT NULL CHECK (length(tuple_digest) = 64 AND tuple_digest NOT GLOB '*[^0-9a-f]*'),
  purpose TEXT NOT NULL CHECK (purpose = 'base_manifest_sign_v1'),
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  candidate_digest TEXT NOT NULL CHECK (length(candidate_digest) = 64 AND candidate_digest NOT GLOB '*[^0-9a-f]*'),
  head_digest TEXT NOT NULL CHECK (
    head_digest = '' OR (length(head_digest) = 64 AND head_digest NOT GLOB '*[^0-9a-f]*')
  ),
  signer_key_id TEXT NOT NULL CHECK (length(signer_key_id) = 64 AND signer_key_id NOT GLOB '*[^0-9a-f]*'),
  logical_bytes INTEGER NOT NULL CHECK (logical_bytes > 0),
  PRIMARY KEY (principal, request_id, operator),
  UNIQUE (principal, request_id, audit_state_version),
  FOREIGN KEY (principal, request_id)
    REFERENCES policy_requests(principal, request_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS policy_heads (
  authority_singleton INTEGER NOT NULL DEFAULT 1 CHECK (authority_singleton = 1),
  authority_id TEXT NOT NULL CHECK (
    length(authority_id) = 38 AND substr(authority_id,1,6) = 'pauth_' AND
    substr(authority_id,7) NOT GLOB '*[^0-9a-f]*'
  ),
  host_key_fp TEXT NOT NULL CHECK (host_key_fp <> ''),
  manifest_envelope BLOB NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  base_digest TEXT NOT NULL CHECK (length(base_digest) = 64 AND base_digest NOT GLOB '*[^0-9a-f]*'),
  epoch_be BLOB NOT NULL CHECK (length(epoch_be) = 8 AND epoch_be <> x'0000000000000000'),
  revision_be BLOB NOT NULL CHECK (length(revision_be) = 8 AND revision_be <> x'0000000000000000'),
  signer_key_id TEXT NOT NULL CHECK (length(signer_key_id) = 64 AND signer_key_id NOT GLOB '*[^0-9a-f]*'),
  signer_public_key BLOB NOT NULL CHECK (length(signer_public_key) = 32),
  row_version INTEGER NOT NULL CHECK (row_version > 0),
  logical_bytes INTEGER NOT NULL CHECK (logical_bytes > 0),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (authority_id, host_key_fp),
  FOREIGN KEY (authority_singleton, authority_id)
    REFERENCES policy_authority_meta(singleton, authority_id)
);

CREATE TRIGGER IF NOT EXISTS policy_meta_immutable
BEFORE UPDATE ON policy_authority_meta
WHEN NEW.singleton IS NOT OLD.singleton OR NEW.authority_id IS NOT OLD.authority_id OR
     NEW.accounting_version IS NOT OLD.accounting_version OR NEW.archive_id IS NOT OLD.archive_id OR
     NEW.max_heads IS NOT OLD.max_heads OR NEW.max_requests IS NOT OLD.max_requests OR
     NEW.max_logical_bytes IS NOT OLD.max_logical_bytes OR NEW.max_active_global IS NOT OLD.max_active_global OR
     NEW.max_active_per_principal IS NOT OLD.max_active_per_principal OR
     NEW.max_votes_per_request IS NOT OLD.max_votes_per_request OR
     NEW.max_rejection_reserved_bytes_per_principal IS NOT OLD.max_rejection_reserved_bytes_per_principal OR
     NEW.config_digest IS NOT OLD.config_digest OR NEW.requester_operator_id IS NOT OLD.requester_operator_id OR
     NEW.required_approvals IS NOT OLD.required_approvals OR NEW.deny_veto IS NOT OLD.deny_veto OR
     NEW.allow_self_approve IS NOT OLD.allow_self_approve OR NEW.policy_voter_role IS NOT OLD.policy_voter_role OR
     NEW.voter_eligibility_version IS NOT OLD.voter_eligibility_version OR
     NEW.vote_step_up_required IS NOT OLD.vote_step_up_required OR
     NEW.vote_auth_methods_json IS NOT OLD.vote_auth_methods_json OR
     NEW.review_renderer_version IS NOT OLD.review_renderer_version OR
     NEW.review_rules_digest IS NOT OLD.review_rules_digest OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'policy authority metadata is immutable'); END;

CREATE TRIGGER IF NOT EXISTS policy_meta_no_delete
BEFORE DELETE ON policy_authority_meta
BEGIN SELECT RAISE(ABORT, 'policy authority metadata cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS policy_key_binding_limit
BEFORE INSERT ON policy_authority_key_bindings
WHEN (SELECT count(*) FROM policy_authority_key_bindings) >= 256
BEGIN SELECT RAISE(ABORT, 'policy authority key binding limit'); END;

CREATE TRIGGER IF NOT EXISTS policy_key_binding_immutable
BEFORE UPDATE ON policy_authority_key_bindings
BEGIN SELECT RAISE(ABORT, 'policy authority key bindings are immutable'); END;

CREATE TRIGGER IF NOT EXISTS policy_key_binding_no_delete
BEFORE DELETE ON policy_authority_key_bindings
BEGIN SELECT RAISE(ABORT, 'policy authority key bindings cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_no_delete
BEFORE DELETE ON policy_requests
BEGIN SELECT RAISE(ABORT, 'policy requests cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_insert_guard_zero
BEFORE INSERT ON policy_requests
WHEN NEW.compaction_delete_guard <> 0
BEGIN SELECT RAISE(ABORT, 'policy request cannot be inserted with compaction guard'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_permanent_immutable
BEFORE UPDATE ON policy_requests
WHEN NEW.principal IS NOT OLD.principal OR NEW.request_id IS NOT OLD.request_id OR
     NEW.review_id IS NOT OLD.review_id OR NEW.authority_singleton IS NOT OLD.authority_singleton OR
     NEW.authority_id IS NOT OLD.authority_id OR NEW.purpose IS NOT OLD.purpose OR
     NEW.tuple_digest IS NOT OLD.tuple_digest OR NEW.payload_sha256 IS NOT OLD.payload_sha256 OR
     NEW.base_digest IS NOT OLD.base_digest OR NEW.host_key_fp IS NOT OLD.host_key_fp OR
     NEW.expected_head_digest IS NOT OLD.expected_head_digest OR
     NEW.expected_signer_key_id IS NOT OLD.expected_signer_key_id OR NEW.bootstrap IS NOT OLD.bootstrap OR
     NEW.epoch_be IS NOT OLD.epoch_be OR NEW.revision_be IS NOT OLD.revision_be OR
     NEW.miss_action IS NOT OLD.miss_action OR NEW.growth IS NOT OLD.growth OR
     NEW.entry_count IS NOT OLD.entry_count OR NEW.revocation_count IS NOT OLD.revocation_count OR
     NEW.logical_change_count IS NOT OLD.logical_change_count OR
     NEW.vote_step_up_required IS NOT OLD.vote_step_up_required OR
     NEW.vote_auth_methods_json IS NOT OLD.vote_auth_methods_json OR
     NEW.vote_auth_methods_sha256 IS NOT OLD.vote_auth_methods_sha256 OR
     NEW.required_approvals IS NOT OLD.required_approvals OR NEW.deny_veto IS NOT OLD.deny_veto OR
     NEW.allow_self_approve IS NOT OLD.allow_self_approve OR
     NEW.requester_principal IS NOT OLD.requester_principal OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'policy request immutable field changed'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_full_fields_immutable
BEFORE UPDATE ON policy_requests
WHEN NOT (OLD.storage_kind = 'full' AND NEW.storage_kind = 'tombstone') AND (
     NEW.canonical_request IS NOT OLD.canonical_request OR NEW.payload IS NOT OLD.payload OR
     NEW.trusted_head_envelope IS NOT OLD.trusted_head_envelope OR
     NEW.trusted_head_digest IS NOT OLD.trusted_head_digest OR NEW.trusted_head_key_id IS NOT OLD.trusted_head_key_id OR
     NEW.trusted_head_public_key IS NOT OLD.trusted_head_public_key OR
     NEW.trusted_head_epoch_be IS NOT OLD.trusted_head_epoch_be OR
     NEW.trusted_head_revision_be IS NOT OLD.trusted_head_revision_be OR
     NEW.trusted_head_row_version IS NOT OLD.trusted_head_row_version OR
     NEW.frozen_signer_key_id IS NOT OLD.frozen_signer_key_id OR
     NEW.frozen_signer_public_key IS NOT OLD.frozen_signer_public_key OR
     NEW.review_json IS NOT OLD.review_json OR NEW.review_sha256 IS NOT OLD.review_sha256 OR
     NEW.review_rendered_bytes IS NOT OLD.review_rendered_bytes OR
     NEW.review_item_count IS NOT OLD.review_item_count OR
     NEW.review_renderer_version IS NOT OLD.review_renderer_version OR
     NEW.review_rules_digest IS NOT OLD.review_rules_digest OR
     NEW.eligible_voters_json IS NOT OLD.eligible_voters_json OR
     NEW.eligible_voters_sha256 IS NOT OLD.eligible_voters_sha256 OR
     NEW.eligible_voter_count IS NOT OLD.eligible_voter_count OR
     NEW.pending_response IS NOT OLD.pending_response)
BEGIN SELECT RAISE(ABORT, 'policy request full immutable field changed'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_claimed_head_set_once
BEFORE UPDATE ON policy_requests
WHEN NOT (OLD.storage_kind = 'full' AND NEW.storage_kind = 'tombstone') AND (
     (OLD.claimed_head_envelope IS NOT NULL AND NEW.claimed_head_envelope IS NOT OLD.claimed_head_envelope) OR
     (OLD.claimed_head_digest IS NOT NULL AND NEW.claimed_head_digest IS NOT OLD.claimed_head_digest) OR
     (OLD.claimed_head_key_id IS NOT NULL AND NEW.claimed_head_key_id IS NOT OLD.claimed_head_key_id) OR
     (OLD.claimed_head_public_key IS NOT NULL AND NEW.claimed_head_public_key IS NOT OLD.claimed_head_public_key) OR
     (OLD.claimed_head_epoch_be IS NOT NULL AND NEW.claimed_head_epoch_be IS NOT OLD.claimed_head_epoch_be) OR
     (OLD.claimed_head_revision_be IS NOT NULL AND NEW.claimed_head_revision_be IS NOT OLD.claimed_head_revision_be) OR
     (OLD.claimed_head_row_version IS NOT NULL AND NEW.claimed_head_row_version IS NOT OLD.claimed_head_row_version))
BEGIN SELECT RAISE(ABORT, 'policy claimed head is set once'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_set_once_fields
BEFORE UPDATE ON policy_requests
WHEN (OLD.no_op = 1 AND NEW.no_op <> 1) OR
     (OLD.error_family <> '' AND (NEW.error_family IS NOT OLD.error_family OR NEW.failure_code IS NOT OLD.failure_code)) OR
     (OLD.result_envelope IS NOT NULL AND NOT (OLD.storage_kind = 'full' AND NEW.storage_kind = 'tombstone') AND
       (NEW.result_envelope IS NOT OLD.result_envelope OR NEW.result_sha256 IS NOT OLD.result_sha256)) OR
     (OLD.terminal_response IS NOT NULL AND NOT (OLD.storage_kind = 'full' AND NEW.storage_kind = 'tombstone') AND
       (NEW.terminal_response IS NOT OLD.terminal_response OR NEW.terminal_http_status IS NOT OLD.terminal_http_status OR
        NEW.resolved_at IS NOT OLD.resolved_at)) OR
     (OLD.archive_id IS NOT NULL AND (NEW.archive_id IS NOT OLD.archive_id OR
       NEW.archive_object_sha256 IS NOT OLD.archive_object_sha256 OR
       NEW.archive_record_bytes IS NOT OLD.archive_record_bytes OR
       NEW.terminal_response_sha256 IS NOT OLD.terminal_response_sha256 OR
       NEW.terminal_response_bytes IS NOT OLD.terminal_response_bytes))
BEGIN SELECT RAISE(ABORT, 'policy request set-once field changed'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_audit_monotone
BEFORE UPDATE ON policy_requests
WHEN NEW.submission_audited < OLD.submission_audited OR
     NEW.pre_mint_audited < OLD.pre_mint_audited OR NEW.result_audited < OLD.result_audited OR
     NEW.terminal_audited < OLD.terminal_audited OR
     ((NEW.submission_audited IS NOT OLD.submission_audited OR
       NEW.pre_mint_audited IS NOT OLD.pre_mint_audited OR
       NEW.result_audited IS NOT OLD.result_audited OR
       NEW.terminal_audited IS NOT OLD.terminal_audited) AND
      ((NEW.submission_audited IS NOT OLD.submission_audited) +
       (NEW.pre_mint_audited IS NOT OLD.pre_mint_audited) +
       (NEW.result_audited IS NOT OLD.result_audited) +
       (NEW.terminal_audited IS NOT OLD.terminal_audited) <> 1 OR
       NEW.storage_kind IS NOT OLD.storage_kind OR NEW.state IS NOT OLD.state OR
       NEW.state_version IS NOT OLD.state_version OR NEW.no_op IS NOT OLD.no_op OR
       NEW.error_family IS NOT OLD.error_family OR NEW.failure_code IS NOT OLD.failure_code OR
       NEW.claimed_head_envelope IS NOT OLD.claimed_head_envelope OR
       NEW.claimed_head_digest IS NOT OLD.claimed_head_digest OR
       NEW.claimed_head_key_id IS NOT OLD.claimed_head_key_id OR
       NEW.claimed_head_public_key IS NOT OLD.claimed_head_public_key OR
       NEW.claimed_head_epoch_be IS NOT OLD.claimed_head_epoch_be OR
       NEW.claimed_head_revision_be IS NOT OLD.claimed_head_revision_be OR
       NEW.claimed_head_row_version IS NOT OLD.claimed_head_row_version OR
       NEW.result_envelope IS NOT OLD.result_envelope OR NEW.result_sha256 IS NOT OLD.result_sha256 OR
       NEW.terminal_response IS NOT OLD.terminal_response OR
       NEW.terminal_http_status IS NOT OLD.terminal_http_status OR
       NEW.reserved_bytes IS NOT OLD.reserved_bytes OR
       NEW.recovery_lease_owner IS NOT OLD.recovery_lease_owner OR
       NEW.recovery_lease_until IS NOT OLD.recovery_lease_until OR
       NEW.recovery_lease_generation IS NOT OLD.recovery_lease_generation OR
       NEW.archive_id IS NOT OLD.archive_id OR NEW.archive_object_sha256 IS NOT OLD.archive_object_sha256 OR
       NEW.archive_record_bytes IS NOT OLD.archive_record_bytes OR
       NEW.terminal_response_sha256 IS NOT OLD.terminal_response_sha256 OR
       NEW.terminal_response_bytes IS NOT OLD.terminal_response_bytes OR
       NEW.compaction_delete_guard IS NOT OLD.compaction_delete_guard OR
       NEW.logical_bytes IS NOT OLD.logical_bytes OR NEW.updated_at IS NOT OLD.updated_at OR
       NEW.resolved_at IS NOT OLD.resolved_at))
BEGIN SELECT RAISE(ABORT, 'policy audit acknowledgement is monotone and reservation-neutral'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_reservation_monotone
BEFORE UPDATE ON policy_requests
WHEN NEW.reserved_bytes > OLD.reserved_bytes
BEGIN SELECT RAISE(ABORT, 'policy reservation cannot increase'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_clock_generation_monotone
BEFORE UPDATE ON policy_requests
WHEN NEW.updated_at < OLD.updated_at OR NEW.recovery_lease_generation < OLD.recovery_lease_generation
BEGIN SELECT RAISE(ABORT, 'policy request clock/generation cannot decrease'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_state_version
BEFORE UPDATE ON policy_requests
WHEN NOT (
  (NEW.state = OLD.state AND NEW.state_version = OLD.state_version) OR
  (OLD.state = 'pending' AND NEW.state = 'pending' AND NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'received_unaudited' AND NEW.state = 'pending' AND NEW.state_version = OLD.state_version) OR
  (OLD.state = 'received_unaudited' AND NEW.state IN ('no_op_unexposed','error_received') AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'rejection_unaudited' AND NEW.state = 'rejection_error_received' AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'pending' AND NEW.state IN ('approved_materializing','denial_received','error_received') AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'approved_materializing' AND NEW.state IN ('approved_unexposed','error_received') AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'approved_unexposed' AND NEW.state = 'error_received' AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'no_op_unexposed' AND NEW.state = 'error_received' AND
    NEW.state_version = OLD.state_version + 1) OR
  (OLD.state = 'approved_unexposed' AND NEW.state = 'approved' AND NEW.state_version = OLD.state_version) OR
  (OLD.state = 'no_op_unexposed' AND NEW.state = 'approved' AND NEW.state_version = OLD.state_version) OR
  (OLD.state = 'denial_received' AND NEW.state = 'denied' AND NEW.state_version = OLD.state_version) OR
  (OLD.state IN ('error_received','rejection_error_received') AND NEW.state = 'error' AND
    NEW.state_version = OLD.state_version)
)
BEGIN SELECT RAISE(ABORT, 'illegal policy state/version transition'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_error_source_fence
BEFORE UPDATE ON policy_requests
WHEN OLD.state IS NOT NEW.state AND NEW.state IN ('rejection_error_received','error_received') AND NOT (
  NEW.no_op IS OLD.no_op AND NEW.result_envelope IS OLD.result_envelope AND
  NEW.result_sha256 IS OLD.result_sha256 AND
  NEW.claimed_head_envelope IS OLD.claimed_head_envelope AND
  NEW.claimed_head_digest IS OLD.claimed_head_digest AND NEW.claimed_head_key_id IS OLD.claimed_head_key_id AND
  NEW.claimed_head_public_key IS OLD.claimed_head_public_key AND
  NEW.claimed_head_epoch_be IS OLD.claimed_head_epoch_be AND
  NEW.claimed_head_revision_be IS OLD.claimed_head_revision_be AND
  NEW.claimed_head_row_version IS OLD.claimed_head_row_version AND
  ((OLD.state = 'rejection_unaudited' AND NEW.state = 'rejection_error_received' AND
    NEW.error_family = OLD.error_family AND NEW.failure_code = OLD.failure_code) OR
   (OLD.state = 'received_unaudited' AND NEW.state = 'error_received' AND
    NEW.error_family = 'processing-error' AND NEW.failure_code = 'signer_key_changed') OR
   (OLD.state = 'pending' AND NEW.state = 'error_received' AND
    NEW.error_family = 'semantic-rejection' AND NEW.failure_code = 'quorum_unattainable') OR
   (OLD.state = 'approved_materializing' AND NEW.state = 'error_received' AND
    NEW.error_family = 'processing-error' AND NEW.failure_code IN (
      'signer_key_changed','stale_policy_head','policy_materialization_failed')) OR
   (OLD.state IN ('approved_unexposed','no_op_unexposed') AND NEW.state = 'error_received' AND
    NEW.error_family = 'publication-error' AND NEW.failure_code IN ('signer_key_changed','stale_policy_head')))
)
BEGIN SELECT RAISE(ABORT, 'illegal policy error source/family/code transition'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_terminal_publication_fence
BEFORE UPDATE ON policy_requests
WHEN OLD.state NOT IN ('approved','denied','error') AND NEW.state IN ('approved','denied','error') AND NOT (
  NEW.result_envelope IS OLD.result_envelope AND NEW.result_sha256 IS OLD.result_sha256 AND
  NEW.no_op IS OLD.no_op AND NEW.error_family IS OLD.error_family AND NEW.failure_code IS OLD.failure_code AND
  NEW.claimed_head_envelope IS OLD.claimed_head_envelope AND
  NEW.claimed_head_digest IS OLD.claimed_head_digest AND NEW.claimed_head_key_id IS OLD.claimed_head_key_id AND
  NEW.claimed_head_public_key IS OLD.claimed_head_public_key AND
  NEW.claimed_head_epoch_be IS OLD.claimed_head_epoch_be AND
  NEW.claimed_head_revision_be IS OLD.claimed_head_revision_be AND
  NEW.claimed_head_row_version IS OLD.claimed_head_row_version
)
BEGIN SELECT RAISE(ABORT, 'terminal publication changed staged result'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_same_state_reservation
BEFORE UPDATE ON policy_requests
WHEN NEW.state = OLD.state AND NEW.reserved_bytes IS NOT OLD.reserved_bytes AND
	 NOT ((OLD.state = 'pending' AND NEW.state_version = OLD.state_version + 1) OR
	      (OLD.recovery_lease_owner = '' AND OLD.recovery_lease_until = 0 AND
	       OLD.recovery_lease_generation = 0 AND NEW.recovery_lease_owner <> '' AND
	       NEW.recovery_lease_until > 0 AND NEW.recovery_lease_generation = 1 AND
	       OLD.state_version = NEW.state_version AND
	       OLD.reserved_bytes = NEW.reserved_bytes + 128 AND
	       NEW.logical_bytes + NEW.reserved_bytes <= OLD.logical_bytes + OLD.reserved_bytes))
BEGIN SELECT RAISE(ABORT, 'reservation changed without a covered write'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_matrix_2b_fence
BEFORE UPDATE ON policy_requests
WHEN OLD.storage_kind = 'full' AND OLD.state = 'pending' AND OLD.error_family = '' AND
     NEW.state = 'error_received' AND NEW.error_family = 'semantic-rejection' AND
     NEW.failure_code = 'quorum_unattainable' AND NOT (
       NEW.canonical_request IS OLD.canonical_request AND NEW.payload IS OLD.payload AND
       NEW.trusted_head_envelope IS OLD.trusted_head_envelope AND
       NEW.trusted_head_public_key IS OLD.trusted_head_public_key AND
       NEW.trusted_head_epoch_be IS OLD.trusted_head_epoch_be AND
       NEW.trusted_head_revision_be IS OLD.trusted_head_revision_be AND
       NEW.claimed_head_envelope IS OLD.claimed_head_envelope AND
       NEW.claimed_head_public_key IS OLD.claimed_head_public_key AND
       NEW.claimed_head_epoch_be IS OLD.claimed_head_epoch_be AND
       NEW.claimed_head_revision_be IS OLD.claimed_head_revision_be AND
       NEW.frozen_signer_public_key IS OLD.frozen_signer_public_key AND
       NEW.epoch_be IS OLD.epoch_be AND NEW.revision_be IS OLD.revision_be AND
       NEW.review_json IS OLD.review_json AND NEW.eligible_voters_json IS OLD.eligible_voters_json AND
       NEW.vote_auth_methods_json IS OLD.vote_auth_methods_json AND
       NEW.pending_response IS OLD.pending_response AND
       NEW.result_envelope IS NULL AND OLD.result_envelope IS NULL AND
       NEW.terminal_response IS NULL AND OLD.terminal_response IS NULL AND
       NEW.reserved_bytes <= OLD.reserved_bytes AND
       NEW.logical_bytes + NEW.reserved_bytes <= OLD.logical_bytes + OLD.reserved_bytes
     )
BEGIN SELECT RAISE(ABORT, 'illegal quorum-unattainable conversion'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_storage_guard
BEFORE UPDATE ON policy_requests
WHEN NOT (
  (OLD.storage_kind = NEW.storage_kind AND OLD.compaction_delete_guard = 0 AND
    NEW.compaction_delete_guard = 0) OR
  (OLD.storage_kind = 'full' AND OLD.compaction_delete_guard = 0 AND
    NEW.storage_kind = 'tombstone' AND NEW.compaction_delete_guard = 1 AND
    OLD.state IN ('approved','denied','error') AND NEW.state = OLD.state AND
    NEW.state_version = OLD.state_version AND NEW.submission_audited = OLD.submission_audited AND
    NEW.pre_mint_audited = OLD.pre_mint_audited AND NEW.result_audited = OLD.result_audited AND
    NEW.terminal_audited = OLD.terminal_audited AND NEW.no_op = OLD.no_op AND
    NEW.error_family = OLD.error_family AND NEW.failure_code = OLD.failure_code AND
    NEW.result_sha256 = OLD.result_sha256 AND NEW.terminal_http_status = OLD.terminal_http_status AND
    NEW.reserved_bytes = OLD.reserved_bytes AND NEW.recovery_lease_owner = OLD.recovery_lease_owner AND
    NEW.recovery_lease_until = OLD.recovery_lease_until AND
    NEW.recovery_lease_generation = OLD.recovery_lease_generation AND
    NEW.created_at = OLD.created_at AND NEW.updated_at = OLD.updated_at AND NEW.resolved_at = OLD.resolved_at AND
    NEW.archive_id = (SELECT archive_id FROM policy_authority_meta WHERE singleton = 1) AND
    NEW.logical_bytes + NEW.reserved_bytes <= OLD.logical_bytes + OLD.reserved_bytes) OR
  (OLD.storage_kind = 'tombstone' AND OLD.compaction_delete_guard = 1 AND
    NEW.storage_kind = 'tombstone' AND NEW.compaction_delete_guard = 0 AND
    NEW.state IS OLD.state AND NEW.state_version IS OLD.state_version AND
    NEW.logical_bytes IS OLD.logical_bytes AND NEW.updated_at IS OLD.updated_at)
)
BEGIN SELECT RAISE(ABORT, 'illegal policy compaction guard transition'); END;

CREATE TRIGGER IF NOT EXISTS policy_request_compact_votes
AFTER UPDATE OF storage_kind ON policy_requests
WHEN OLD.storage_kind = 'full' AND OLD.compaction_delete_guard = 0 AND
     NEW.storage_kind = 'tombstone' AND NEW.compaction_delete_guard = 1
BEGIN
  DELETE FROM policy_votes WHERE principal = NEW.principal AND request_id = NEW.request_id;
  UPDATE policy_requests SET compaction_delete_guard = 0
    WHERE principal = NEW.principal AND request_id = NEW.request_id AND
          storage_kind = 'tombstone' AND compaction_delete_guard = 1;
END;

CREATE TRIGGER IF NOT EXISTS policy_vote_parent_pending
BEFORE INSERT ON policy_votes
WHEN NOT EXISTS (
  SELECT 1 FROM policy_requests r
  WHERE r.principal = NEW.principal AND r.request_id = NEW.request_id AND
        r.storage_kind = 'full' AND r.state = 'pending' AND r.compaction_delete_guard = 0 AND
        r.state_version = NEW.audit_state_version AND r.frozen_signer_key_id = NEW.signer_key_id
) OR (SELECT count(*) FROM policy_votes v
      WHERE v.principal = NEW.principal AND v.request_id = NEW.request_id) >= 256
BEGIN SELECT RAISE(ABORT, 'policy vote requires pending parent and capacity'); END;

CREATE TRIGGER IF NOT EXISTS policy_vote_immutable
BEFORE UPDATE ON policy_votes
WHEN NOT (OLD.audited = 0 AND NEW.audited = 1 AND
  NEW.principal IS OLD.principal AND NEW.request_id IS OLD.request_id AND
  NEW.operator IS OLD.operator AND NEW.decision IS OLD.decision AND
  NEW.authn_method IS OLD.authn_method AND NEW.ts IS OLD.ts AND
  NEW.audit_state_version IS OLD.audit_state_version AND NEW.tuple_digest IS OLD.tuple_digest AND
  NEW.purpose IS OLD.purpose AND NEW.payload_sha256 IS OLD.payload_sha256 AND
  NEW.candidate_digest IS OLD.candidate_digest AND NEW.head_digest IS OLD.head_digest AND
  NEW.signer_key_id IS OLD.signer_key_id AND NEW.logical_bytes IS OLD.logical_bytes)
BEGIN SELECT RAISE(ABORT, 'policy vote is immutable except audited 0 to 1'); END;

CREATE TRIGGER IF NOT EXISTS policy_vote_delete_guard
BEFORE DELETE ON policy_votes
WHEN NOT EXISTS (
  SELECT 1 FROM policy_requests r
  WHERE r.principal = OLD.principal AND r.request_id = OLD.request_id AND
        r.storage_kind = 'tombstone' AND r.compaction_delete_guard = 1
)
BEGIN SELECT RAISE(ABORT, 'policy votes may be deleted only by compaction'); END;

CREATE TRIGGER IF NOT EXISTS policy_head_no_delete
BEFORE DELETE ON policy_heads
BEGIN SELECT RAISE(ABORT, 'policy heads cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS policy_head_update_guard
BEFORE UPDATE ON policy_heads
WHEN NEW.authority_singleton IS NOT OLD.authority_singleton OR
     NEW.authority_id IS NOT OLD.authority_id OR NEW.host_key_fp IS NOT OLD.host_key_fp OR
     NEW.row_version <> OLD.row_version + 1 OR
     NEW.manifest_envelope IS OLD.manifest_envelope OR NEW.payload_sha256 IS OLD.payload_sha256 OR
     NEW.base_digest IS OLD.base_digest OR
     NEW.epoch_be < OLD.epoch_be OR
     (NEW.epoch_be = OLD.epoch_be AND NEW.revision_be <= OLD.revision_be) OR
     NEW.updated_at <= OLD.updated_at
BEGIN SELECT RAISE(ABORT, 'illegal policy head successor update'); END;
`

var policySchemaColumns = map[string][]string{
	"policy_authority_meta": {
		"singleton", "authority_id", "accounting_version", "archive_id", "max_heads", "max_requests",
		"max_logical_bytes", "max_active_global", "max_active_per_principal", "max_votes_per_request",
		"max_rejection_reserved_bytes_per_principal", "config_digest", "requester_operator_id",
		"required_approvals", "deny_veto", "allow_self_approve", "policy_voter_role",
		"voter_eligibility_version", "vote_step_up_required", "vote_auth_methods_json",
		"review_renderer_version", "review_rules_digest", "logical_used_bytes", "logical_reserved_bytes",
		"full_request_count", "head_count", "active_count", "created_at",
	},
	"policy_authority_key_bindings": {"signer_key_id", "signer_public_key", "authority_id", "created_at"},
	"policy_requests": {
		"principal", "request_id", "review_id", "authority_singleton", "authority_id", "storage_kind",
		"purpose", "canonical_request", "payload", "tuple_digest", "payload_sha256", "base_digest",
		"host_key_fp", "expected_head_digest", "expected_signer_key_id", "bootstrap",
		"trusted_head_envelope", "trusted_head_digest", "trusted_head_key_id", "trusted_head_public_key",
		"trusted_head_epoch_be", "trusted_head_revision_be", "trusted_head_row_version",
		"claimed_head_envelope", "claimed_head_digest", "claimed_head_key_id", "claimed_head_public_key",
		"claimed_head_epoch_be", "claimed_head_revision_be", "claimed_head_row_version",
		"frozen_signer_key_id", "frozen_signer_public_key", "epoch_be", "revision_be", "miss_action", "growth",
		"entry_count", "revocation_count", "logical_change_count", "review_json", "review_sha256",
		"review_rendered_bytes", "review_item_count", "review_renderer_version", "review_rules_digest",
		"eligible_voters_json", "eligible_voters_sha256", "eligible_voter_count", "vote_step_up_required",
		"vote_auth_methods_json", "vote_auth_methods_sha256", "required_approvals", "deny_veto",
		"allow_self_approve", "requester_principal", "state", "state_version", "submission_audited",
		"pre_mint_audited", "result_audited", "terminal_audited", "no_op", "error_family", "failure_code",
		"result_envelope", "result_sha256", "pending_response", "terminal_response", "terminal_http_status",
		"reserved_bytes", "recovery_lease_owner", "recovery_lease_until", "recovery_lease_generation",
		"archive_id", "archive_object_sha256", "archive_record_bytes", "terminal_response_sha256",
		"terminal_response_bytes", "compaction_delete_guard", "logical_bytes", "created_at", "updated_at", "resolved_at",
	},
	"policy_votes": {
		"principal", "request_id", "operator", "decision", "authn_method", "ts", "audited",
		"audit_state_version", "tuple_digest", "purpose", "payload_sha256", "candidate_digest",
		"head_digest", "signer_key_id", "logical_bytes",
	},
	"policy_heads": {
		"authority_singleton", "authority_id", "host_key_fp", "manifest_envelope", "payload_sha256",
		"base_digest", "epoch_be", "revision_be", "signer_key_id", "signer_public_key", "row_version",
		"logical_bytes", "updated_at",
	},
}

var policySchemaObjects = map[string]string{
	"policy_authority_meta":                     "table",
	"policy_authority_key_bindings":             "table",
	"policy_requests":                           "table",
	"policy_votes":                              "table",
	"policy_heads":                              "table",
	"policy_one_active_host":                    "index",
	"policy_pending_created":                    "index",
	"policy_rejection_budget":                   "index",
	"policy_meta_immutable":                     "trigger",
	"policy_meta_no_delete":                     "trigger",
	"policy_key_binding_limit":                  "trigger",
	"policy_key_binding_immutable":              "trigger",
	"policy_key_binding_no_delete":              "trigger",
	"policy_request_no_delete":                  "trigger",
	"policy_request_insert_guard_zero":          "trigger",
	"policy_request_permanent_immutable":        "trigger",
	"policy_request_full_fields_immutable":      "trigger",
	"policy_request_claimed_head_set_once":      "trigger",
	"policy_request_set_once_fields":            "trigger",
	"policy_request_audit_monotone":             "trigger",
	"policy_request_reservation_monotone":       "trigger",
	"policy_request_clock_generation_monotone":  "trigger",
	"policy_request_state_version":              "trigger",
	"policy_request_error_source_fence":         "trigger",
	"policy_request_terminal_publication_fence": "trigger",
	"policy_request_same_state_reservation":     "trigger",
	"policy_request_matrix_2b_fence":            "trigger",
	"policy_request_storage_guard":              "trigger",
	"policy_request_compact_votes":              "trigger",
	"policy_vote_parent_pending":                "trigger",
	"policy_vote_immutable":                     "trigger",
	"policy_vote_delete_guard":                  "trigger",
	"policy_head_no_delete":                     "trigger",
	"policy_head_update_guard":                  "trigger",
}

type policySchemaObject struct {
	objectType string
	sql        string
}

var (
	policySchemaOracleOnce sync.Once
	policySchemaOracle     map[string]policySchemaObject
	policySchemaOracleErr  error
)

func applyMigration6(ctx context.Context, connection migrationExecutor, migrationSQL string) error {
	if _, err := connection.ExecContext(ctx, migrationSQL); err != nil {
		return fmt.Errorf("apply policy schema: %w", err)
	}
	return verifyPolicySchema(ctx, connection)
}

func verifyPolicySchema(ctx context.Context, connection migrationExecutor) error {
	expectedObjects, err := canonicalPolicySchemaObjects()
	if err != nil {
		return err
	}
	for table, want := range policySchemaColumns {
		got, err := tableColumns(ctx, connection, table)
		if err != nil {
			return err
		}
		if len(got) != len(want) {
			return fmt.Errorf("policy schema table %s has %d columns; want %d", table, len(got), len(want))
		}
		for index := range want {
			if got[index] != want[index] {
				return fmt.Errorf("policy schema table %s column %d is %q; want %q", table, index+1, got[index], want[index])
			}
		}
	}
	actualObjects, err := readPolicySchemaObjects(ctx, connection)
	if err != nil {
		return err
	}
	for name, actual := range actualObjects {
		wantType, ok := policySchemaObjects[name]
		if !ok {
			return fmt.Errorf("unexpected policy schema object %s %s", actual.objectType, name)
		}
		if actual.objectType != wantType {
			return fmt.Errorf("policy schema object %s has type %s; want %s", name, actual.objectType, wantType)
		}
		if expectedObjects[name].sql != actual.sql {
			return fmt.Errorf("policy schema object %s SQL differs from migration 6", name)
		}
	}
	for name := range policySchemaObjects {
		if _, ok := actualObjects[name]; !ok {
			return fmt.Errorf("missing policy schema object %s", name)
		}
	}
	return nil
}

func canonicalPolicySchemaObjects() (map[string]policySchemaObject, error) {
	policySchemaOracleOnce.Do(func() {
		database, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			policySchemaOracleErr = fmt.Errorf("open policy schema oracle: %w", err)
			return
		}
		database.SetMaxOpenConns(1)
		database.SetMaxIdleConns(1)
		defer database.Close()
		ctx := context.Background()
		if _, err := database.ExecContext(ctx, policyMigration6SQL); err != nil {
			policySchemaOracleErr = fmt.Errorf("construct policy schema oracle: %w", err)
			return
		}
		policySchemaOracle, policySchemaOracleErr = readPolicySchemaObjects(ctx, database)
		if policySchemaOracleErr != nil {
			policySchemaOracleErr = fmt.Errorf("read policy schema oracle: %w", policySchemaOracleErr)
			return
		}
		for name, wantType := range policySchemaObjects {
			object, ok := policySchemaOracle[name]
			if !ok || object.objectType != wantType {
				policySchemaOracleErr = fmt.Errorf("migration 6 oracle lacks %s %s", wantType, name)
				return
			}
		}
	})
	return policySchemaOracle, policySchemaOracleErr
}

func readPolicySchemaObjects(ctx context.Context, connection migrationExecutor) (map[string]policySchemaObject, error) {
	rows, err := connection.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master WHERE name GLOB 'policy_*' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("inspect policy schema objects: %w", err)
	}
	defer rows.Close()
	objects := make(map[string]policySchemaObject, len(policySchemaObjects))
	for rows.Next() {
		var objectType, name, definition string
		if err := rows.Scan(&objectType, &name, &definition); err != nil {
			return nil, fmt.Errorf("scan policy schema object: %w", err)
		}
		objects[name] = policySchemaObject{objectType: objectType, sql: definition}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy schema objects: %w", err)
	}
	return objects, nil
}

func tableColumns(ctx context.Context, connection migrationExecutor, table string) ([]string, error) {
	rows, err := connection.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, fmt.Errorf("inspect table %s: %w", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var (
			columnID     int
			name         string
			typeName     string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(&columnID, &name, &typeName, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("scan table %s: %w", table, err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate table %s: %w", table, err)
	}
	return columns, nil
}
