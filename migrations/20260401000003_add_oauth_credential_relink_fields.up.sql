ALTER TABLE oauth_credentials
ADD COLUMN IF NOT EXISTS relink_required_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS relink_reason TEXT;
