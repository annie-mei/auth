ALTER TABLE auth.oauth_credentials
DROP COLUMN IF EXISTS relink_reason,
DROP COLUMN IF EXISTS relink_required_at;
