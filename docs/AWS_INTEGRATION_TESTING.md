# Real AWS S3 Integration Testing (Opt-In)

Status: **prepared but not run in this build.** No AWS bucket, credentials, or
endpoint exist in this repository, and the S3 adapter has not been exercised
against real AWS from this codebase. The tests exist so an operator with an
explicitly approved test bucket can verify the adapter end to end. Until that
run happens and its output is recorded, no live verification of the S3 adapter
is claimed.

The default unit suite (`python -m pytest backend/tests/ -q`) never touches
AWS. The integration module is collected but skipped, and it is reported as
skipped (`NOT RUN`), never as passed.

## What these tests prove and do not prove

These tests use real boto3 clients, real AWS S3 requests, and a real bucket:

- Conditional-write support in the installed SDK
  (`PutObject` with `IfNoneMatch: "*"` and `412 PreconditionFailed` on the
  loser), which is the documented minimum for `boto3>=1.36.0`.
- Real object write/read round trips, idempotent retries, rollback and conflict
  refusal, and tampered-object integrity detection through
  `S3CheckpointStore`.
- The full API path (`POST/GET /api/v1/admin/audit/checkpoints`,
  `GET /api/v1/admin/audit/checkpoints/verify`) with a store built from
  application settings, including `available` semantics, `VALID`/`INVALID`
  outcomes after a chain rewrite, admin-only authorization, and a generic
  `503`/`INCOMPLETE` fail-closed result for an unreachable provider.
- Fail-closed classification of access denial (using public AWS example
  credentials that can access nothing) and of missing credentials (in a
  sanitized subprocess with metadata disabled and no shared credentials).

They do **not** prove or validate:

- A production deployment or the production bucket configuration. API tests
  monkeypatch `AUDIT_ANCHOR_*` settings in-process; they do not endorse any
  `render.yaml`, `docker-compose.yml`, or deployment configuration.
- Bucket versioning, Object Lock retention, IAM policy, or KMS posture beyond
  what the individual request returns. Provider-side resistance to deletion or
  rollback remains an operational configuration concern (see
  [ARCHITECTURE.md](ARCHITECTURE.md)).
- Provider durability. The adapter trusts a successful `PutObject`
  acknowledgement; verification later requires a retrievable, HMAC-valid
  checkpoint and otherwise reports `INCOMPLETE`.
- That an S3-compatible service honors conditional writes and read-after-write
  consistency. These tests target AWS S3. For other services, perform the
  concurrent-write preflight described in ARCHITECTURE.md.

## Prerequisites

1. A Python environment with the project dependencies installed:
   `python -m pip install -r backend/requirements.txt`. Conditional writes
   require `boto3>=1.36.0`, which the requirements file pins as the documented
   minimum.
2. A **dedicated, non-production** S3 bucket that does not contain production
   data. Recommended: a separate AWS account, bucket versioning enabled, and
   Object Lock enabled at bucket creation if retention behavior is part of the
   test goal.
3. A dedicated least-privilege IAM identity with credentials available through
   the AWS default credential chain (environment variables, shared profile, or
   role). Never commit credentials.
4. The bucket name must not contain `prod` or `production`, must equal
   `TRUSTVAULT_AWS_TEST_BUCKET_APPROVAL`, and must differ from any bucket
   configured for application anchoring
   (`AUDIT_ANCHOR_S3_BUCKET`).

## Test-only environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `TRUSTVAULT_AWS_INTEGRATION` | Yes to run | Opt-in gate. Only the exact value `1` enables the module; anything else skips all tests. |
| `TRUSTVAULT_AWS_TEST_BUCKET` | Yes | Dedicated test bucket name. |
| `TRUSTVAULT_AWS_TEST_BUCKET_APPROVAL` | Yes | Must exactly equal `TRUSTVAULT_AWS_TEST_BUCKET`; protects against running destructive cleanup against an unapproved bucket. |
| `TRUSTVAULT_AWS_TEST_REGION` | Yes | AWS region of the test bucket. |
| `TRUSTVAULT_AWS_TEST_PREFIX` | No | Key prefix root; defaults to `trustvault-integration-tests`. Every run appends `/{UTC-timestamp}-{random}`. |

Credentials are resolved by boto3's default chain and may be provided through
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`,
`AWS_PROFILE`, or an attached role. These are standard AWS variables; the tests
never read, log, or store their values.

Application settings such as `AUDIT_ANCHOR_MODE` and `AUDIT_ANCHOR_S3_*` are
**not** test configuration. The API tests monkeypatch them in-process to point
at the approved test bucket and a per-run prefix, so the application itself does
not need to be configured for S3 to run these tests.

## Least-privilege IAM policy

Replace `EXAMPLE-TEST-BUCKET` and adjust the prefix if
`TRUSTVAULT_AWS_TEST_PREFIX` is set to a different root. Delete the
`DeleteObject` statement to prove that a workload without delete rights fails
cleanly, at the cost of leaving test objects behind.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListTestPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::EXAMPLE-TEST-BUCKET",
      "Condition": {
        "StringLike": {
          "s3:prefix": ["trustvault-integration-tests/*"]
        }
      }
    },
    {
      "Sid": "ReadWriteDeleteTestObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::EXAMPLE-TEST-BUCKET/trustvault-integration-tests/*"
    }
  ]
}
```

Deliberately omitted: `s3:BypassGovernanceRetention`,
`s3:PutBucketObjectLockConfiguration`, `s3:PutBucketPolicy`,
`s3:PutBucketVersioning`, and every other bucket-level mutation. The tests do
not need them.

## Exact commands (Windows PowerShell)

```powershell
python -m pip install -r backend/requirements.txt

$env:TRUSTVAULT_AWS_INTEGRATION = "1"
$env:TRUSTVAULT_AWS_TEST_BUCKET = "EXAMPLE-TEST-BUCKET"
$env:TRUSTVAULT_AWS_TEST_BUCKET_APPROVAL = $env:TRUSTVAULT_AWS_TEST_BUCKET
$env:TRUSTVAULT_AWS_TEST_REGION = "eu-west-2"
# Optional: $env:TRUSTVAULT_AWS_TEST_PREFIX = "trustvault-integration-tests"

# Credentials: pick exactly one mechanism
# $env:AWS_PROFILE = "trustvault-integration-test"
# -- or --
# $env:AWS_ACCESS_KEY_ID = "<test-only-access-key-id>"
# $env:AWS_SECRET_ACCESS_KEY = "<test-only-secret-access-key>"
# $env:AWS_SESSION_TOKEN = "<temporary-session-token>"   # if using STS

python -m pytest backend/tests/test_checkpoint_s3_integration.py -m aws_integration -v

# Clear the test gate and credentials when finished
Remove-Item Env:TRUSTVAULT_AWS_INTEGRATION
Remove-Item Env:TRUSTVAULT_AWS_TEST_BUCKET
Remove-Item Env:TRUSTVAULT_AWS_TEST_BUCKET_APPROVAL
Remove-Item Env:TRUSTVAULT_AWS_TEST_REGION
# Remove-Item Env:TRUSTVAULT_AWS_TEST_PREFIX
# Remove-Item Env:AWS_PROFILE
# Remove-Item Env:AWS_ACCESS_KEY_ID
# Remove-Item Env:AWS_SECRET_ACCESS_KEY
# Remove-Item Env:AWS_SESSION_TOKEN
```

Run the complete suite normally (integration skipped):

```powershell
python -m pytest backend/tests/ -q
```

Without `TRUSTVAULT_AWS_INTEGRATION=1`, the integration module reports 8
skipped tests and the rest of the suite is unaffected.

## What each test does

| Test | Verifies |
| --- | --- |
| `test_conditional_put_object_duplicate_is_rejected` | The installed SDK performs `IfNoneMatch: "*"` writes and AWS returns `PreconditionFailed` for the duplicate. |
| `test_real_store_write_read_idempotency_and_refusals` | Real round trip, idempotent retry, rollback refusal, and conflict refusal at the adapter layer. |
| `test_real_store_detects_tampered_object` | An overwritten object with an invalid HMAC raises `CheckpointIntegrityError`. |
| test_api_checkpoint_lifecycle_against_real_bucket | Empty `available: false`, real `201 CREATED`, `available: true`, `VALID`, and post-rewrite `INVALID` through the API, with no bucket/prefix/hash/hmac leakage in responses. |
| test_api_checkpoint_endpoints_require_admin_against_real_bucket | Anonymous `401`, viewer `403`, no anchor objects written, and no checkpoint audit events for denied calls. |
| `test_api_reports_unreachable_provider_as_unavailable` | A real client pointed at an unreachable HTTPS endpoint yields `503` creation, `503` inspection, and `INCOMPLETE` verification (never `VALID`). |
| `test_access_denied_is_classified_against_aws` | Public AWS example credentials produce `CheckpointStoreAccessDeniedError`, not a crash or a false success. Skips if AWS is unreachable from the environment. |
| `test_missing_credentials_fail_closed_in_clean_subprocess` | In a subprocess with all `AWS_*` variables removed, metadata disabled, and no shared credentials file, `read_latest()` raises `CheckpointStoreUnavailableError`. |

## Interpreting results

- **8 skipped with the opt-in reason**: the gate is not set. This is `NOT RUN`;
  it is not verification and must not be cited as one.
- **All passed**: the adapter, factory settings path, API wiring, and
  fail-closed classifications worked in that environment at that time. Record
  the bucket's region, the run date, and the exact command without secrets if
  this needs to be cited.
- **Readiness failure before any test body** (`AWS test bucket readiness check
  failed (...)`): credentials, region, or bucket permissions are wrong. The
  message deliberately omits provider text.
- **Refusal messages about approval, production-looking names, or the
  configured application bucket**: fail-closed safety checks; fix the
  environment, do not weaken the checks.
- **Access-denied test skipped**: the environment cannot reach AWS S3. The
  remaining tests still ran.

## Cleanup

Every run uses a unique prefix
(`{TRUSTVAULT_AWS_TEST_PREFIX}/{UTC timestamp}-{random}`), and module teardown
deletes only objects under that prefix. Nothing outside the run prefix is ever
listed, overwritten, or deleted.

Cleanup is best effort: if the identity lacks `s3:DeleteObject` or an object is
under Object Lock retention, the affected objects remain and a warning is
logged with the count (never the keys). Delete them manually after retention
expires, or use a bucket without Object Lock for repeated test runs. The tests
never request retention bypass, never disable versioning, and never mutate
bucket policy.

## Cost and blast radius

A full run issues a few dozen small S3 requests (list, put, get, delete), with
kilobyte-sized objects. There is no sustained load, no large transfer, and no
bucket-level change. Use a dedicated test bucket/account so a mistake cannot
touch production data.

## Security rules for operators

- Use a dedicated test identity and a dedicated non-production bucket; never
  point these variables at a production bucket or an application anchor bucket.
- Never commit credentials or paste secret values into issues, docs, or commit
  messages. The repository contains no credentials by design.
- One negative test uses the public AWS documentation example access key pair.
  Those values are not secrets and cannot access any account; if AWS is
  unreachable the test skips instead of failing.
- Tests never print captured request bodies, bucket names, prefixes, or
  credential values; failures report only exception type names and fixed
  messages.
