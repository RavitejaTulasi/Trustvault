BEGIN;

CREATE SCHEMA trustvault_audit_anchor
    AUTHORIZATION trustvault_anchor_owner;

REVOKE ALL ON SCHEMA trustvault_audit_anchor FROM PUBLIC;

DO $$
DECLARE
    anchor_database text := current_database();
BEGIN
    EXECUTE format(
        'REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC',
        anchor_database
    );
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO trustvault_anchor_app',
        anchor_database
    );
END
$$;

CREATE TABLE trustvault_audit_anchor.checkpoints (
    stream_id text NOT NULL,
    sequence_number bigint NOT NULL CHECK (sequence_number >= 0),
    record_hash text NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    checkpoint_document text NOT NULL,
    PRIMARY KEY (stream_id, sequence_number)
);

ALTER TABLE trustvault_audit_anchor.checkpoints
    OWNER TO trustvault_anchor_owner;

REVOKE ALL ON SCHEMA trustvault_audit_anchor
    FROM trustvault_anchor_app;
REVOKE ALL ON TABLE trustvault_audit_anchor.checkpoints
    FROM PUBLIC, trustvault_anchor_app;

GRANT USAGE ON SCHEMA trustvault_audit_anchor TO trustvault_anchor_app;
GRANT SELECT, INSERT ON TABLE trustvault_audit_anchor.checkpoints
    TO trustvault_anchor_app;

COMMIT;
