
ALTER TABLE cpeEntry ADD COLUMN IF NOT EXISTS dictionaryEntry BOOLEAN;
ALTER TABLE cpeEntry ALTER COLUMN dictionaryEntry  SET DEFAULT FALSE;
UPDATE cpeEntry SET dictionaryEntry=false;

UPDATE Properties SET value='3.0' WHERE ID='version';