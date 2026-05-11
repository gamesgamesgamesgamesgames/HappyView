ALTER TABLE spaces ADD COLUMN did TEXT;
UPDATE spaces SET did = owner_did;
ALTER TABLE spaces ALTER COLUMN did SET NOT NULL;
CREATE UNIQUE INDEX idx_spaces_did_type_skey ON spaces(did, type_nsid, skey);
