ALTER TABLE reference ALTER COLUMN url SET DATA TYPE VARCHAR(4000);

UPDATE Properties SET `value`='5.6' WHERE ID='version';
