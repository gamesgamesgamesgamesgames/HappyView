ALTER TABLE rate_limits ADD COLUMN default_query_cost INTEGER NOT NULL DEFAULT 1;
ALTER TABLE rate_limits ADD COLUMN default_procedure_cost INTEGER NOT NULL DEFAULT 1;
ALTER TABLE rate_limits ADD COLUMN default_proxy_cost INTEGER NOT NULL DEFAULT 1;
DELETE FROM rate_limits WHERE method IS NOT NULL;
ALTER TABLE lexicons ADD COLUMN token_cost INTEGER;
