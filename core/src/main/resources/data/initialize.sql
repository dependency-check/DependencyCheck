DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS properties;
DROP TABLE IF EXISTS cweEntry;
DROP TABLE IF EXISTS cpeEcosystemCache;
DROP TABLE IF EXISTS knownExploited;
DROP ALIAS IF EXISTS update_vulnerability;
DROP ALIAS IF EXISTS insert_software;


CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1), 
        v2ImpactScore DECIMAL(3,1), v2AcInsufInfo BOOLEAN, v2ObtainAllPrivilege BOOLEAN, 
        v2ObtainUserPrivilege BOOLEAN, v2ObtainOtherPrivilege BOOLEAN, v2UserInteractionRequired BOOLEAN, 
        v2Score DECIMAL(3,1), v2AccessVector VARCHAR(20), v2AccessComplexity VARCHAR(20), 
        v2Authentication VARCHAR(20), v2ConfidentialityImpact VARCHAR(20), v2IntegrityImpact VARCHAR(20), 
        v2AvailabilityImpact VARCHAR(20), v2Version VARCHAR(5), v3ExploitabilityScore DECIMAL(3,1), 
        v3ImpactScore DECIMAL(3,1), v3AttackVector VARCHAR(20), v3AttackComplexity VARCHAR(20), 
        v3PrivilegesRequired VARCHAR(20), v3UserInteraction VARCHAR(20), v3Scope VARCHAR(20), 
        v3ConfidentialityImpact VARCHAR(20), v3IntegrityImpact VARCHAR(20), v3AvailabilityImpact VARCHAR(20), 
        v3BaseScore DECIMAL(3,1), v3BaseSeverity VARCHAR(20), v3Version VARCHAR(5),
        v4version VARCHAR(5), v4attackVector VARCHAR(15), v4attackComplexity VARCHAR(15),
        v4attackRequirements VARCHAR(15), v4privilegesRequired VARCHAR(15), v4userInteraction VARCHAR(15),
        v4vulnConfidentialityImpact VARCHAR(15), v4vulnIntegrityImpact VARCHAR(15), v4vulnAvailabilityImpact VARCHAR(15),
        v4subConfidentialityImpact VARCHAR(15), v4subIntegrityImpact VARCHAR(15),
        v4subAvailabilityImpact VARCHAR(15), v4exploitMaturity VARCHAR(20), v4confidentialityRequirement VARCHAR(15),
        v4integrityRequirement VARCHAR(15), v4availabilityRequirement VARCHAR(15), v4modifiedAttackVector VARCHAR(15),
        v4modifiedAttackComplexity VARCHAR(15), v4modifiedAttackRequirements VARCHAR(15), v4modifiedPrivilegesRequired VARCHAR(15),
        v4modifiedUserInteraction VARCHAR(15), v4modifiedVulnConfidentialityImpact VARCHAR(15), v4modifiedVulnIntegrityImpact VARCHAR(15),
        v4modifiedVulnAvailabilityImpact VARCHAR(15), v4modifiedSubConfidentialityImpact VARCHAR(15), v4modifiedSubIntegrityImpact VARCHAR(15),
        v4modifiedSubAvailabilityImpact VARCHAR(15), v4safety VARCHAR(15), v4automatable VARCHAR(15), v4recovery VARCHAR(15),
        v4valueDensity VARCHAR(15), v4vulnerabilityResponseEffort VARCHAR(15), v4providerUrgency VARCHAR(15),
        v4baseScore DECIMAL(3,1), v4baseSeverity VARCHAR(15), v4threatScore DECIMAL(3,1), v4threatSeverity VARCHAR(15),
        v4environmentalScore DECIMAL(3,1), v4environmentalSeverity VARCHAR(15), v4source VARCHAR(50), v4type VARCHAR(15));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT auto_increment PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(100), versionEndIncluding VARCHAR(100),
                       versionStartExcluding VARCHAR(100), versionStartIncluding VARCHAR(100), vulnerable BOOLEAN
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('unicode', 'international_components_for_unicode', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('icu-project', 'international_components_for_unicode', 'MULTIPLE');

CREATE TABLE knownExploited (cveID varchar(20) PRIMARY KEY,
    vendorProject VARCHAR(255),
    product VARCHAR(255),
    vulnerabilityName VARCHAR(500),
    dateAdded CHAR(10),
    shortDescription VARCHAR(2000),
    requiredAction VARCHAR(1000),
    dueDate CHAR(10),
    notes VARCHAR(2000));

CREATE INDEX idxCwe ON cweEntry(cveid);
CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);

CREATE ALIAS update_vulnerability FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.updateVulnerability";
CREATE ALIAS insert_software FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.insertSoftware";

CREATE ALIAS merge_knownexploited FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.mergeKnownExploited";

CREATE TABLE properties (id varchar(50) PRIMARY KEY, `value` varchar(500));
INSERT INTO properties(id, `value`) VALUES ('version', '5.5');