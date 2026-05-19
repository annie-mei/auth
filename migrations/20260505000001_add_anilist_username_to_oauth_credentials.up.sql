ALTER TABLE annie_auth.oauth_credentials
ADD COLUMN IF NOT EXISTS anilist_username TEXT NULL;
