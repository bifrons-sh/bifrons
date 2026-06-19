-- Add portal_user_id binding to oidc_sessions.
-- Pre-existing rows pre-date the binding feature; '' is fine — the auth code
-- treats empty as "no binding" and forces a re-login when it matters.

ALTER TABLE oidc_sessions ADD COLUMN portal_user_id TEXT NOT NULL DEFAULT '';
