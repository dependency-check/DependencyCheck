--CREATE DATABASE dependencycheck;
--\c dependencycheck;
--CREATE USER dcuser WITH PASSWORD 'DC-Pass1337!';

DROP FUNCTION IF EXISTS public.save_property;
DROP FUNCTION IF EXISTS public.update_vulnerability;
DROP FUNCTION IF EXISTS public.insert_software;
DROP FUNCTION IF EXISTS public.merge_ecosystem;
DROP PROCEDURE IF EXISTS public.merge_knownexploited;
DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS properties;
DROP TABLE IF EXISTS cweEntry;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS cpeEcosystemCache;
DROP TABLE IF EXISTS knownExploited;

CREATE TABLE vulnerability (id SERIAL PRIMARY KEY, cve VARCHAR(20) UNIQUE,
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

CREATE TABLE cpeEntry (id SERIAL PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
    version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
    target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(100), versionEndIncluding VARCHAR(100), 
                       versionStartExcluding VARCHAR(100), versionStartIncluding VARCHAR(100), vulnerable BOOLEAN
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('unicode', 'international_components_for_unicode', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('icu-project', 'international_components_for_unicode', 'MULTIPLE');

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

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
--CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);



CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));

GRANT SELECT, INSERT, DELETE, UPDATE ON ALL TABLES IN SCHEMA public TO dcuser;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public to dcuser;



CREATE FUNCTION save_property (IN prop varchar(50), IN val varchar(500))
RETURNS void
AS $$
UPDATE properties SET "value"=val WHERE id=prop;

INSERT INTO properties (id, value)
	SELECT prop, val
	WHERE NOT EXISTS (SELECT 1 FROM properties WHERE id=prop);
$$ LANGUAGE sql;

GRANT EXECUTE ON FUNCTION public.save_property(varchar(50),varchar(500)) TO dcuser;


CREATE FUNCTION merge_ecosystem (IN p_vendor VARCHAR(255), IN p_product VARCHAR(255), IN p_ecosystem varchar(255))
RETURNS void
AS $$
BEGIN
IF EXISTS(SELECT * FROM cpeEcosystemCache WHERE vendor=p_vendor AND product=p_product) THEN
    UPDATE cpeEcosystemCache SET ecosystem=p_ecosystem WHERE vendor=p_vendor AND product=p_product;
ELSE
    INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES (p_vendor, p_product, p_ecosystem);
END IF;
END
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON FUNCTION public.merge_ecosystem(VARCHAR(255), VARCHAR(255), varchar(255)) TO dcuser;


CREATE PROCEDURE merge_knownexploited (
    IN p_cveID VARCHAR(20),
    IN p_vendorProject VARCHAR(255),
    IN p_product VARCHAR(255),
    IN p_vulnerabilityName VARCHAR(500),
    IN p_dateAdded VARCHAR(10),
    IN p_shortDescription VARCHAR(2000),
    IN p_requiredAction VARCHAR(1000),
    IN p_dueDate VARCHAR(10),
    IN p_notes VARCHAR(2000) default '')
AS $$
BEGIN
IF EXISTS(SELECT 1 FROM knownExploited WHERE cveID=p_cveID) THEN
UPDATE knownExploited
SET vendorProject=p_vendorProject, product=p_product, vulnerabilityName=p_vulnerabilityName,
    dateAdded=p_dateAdded, shortDescription=p_shortDescription, requiredAction=p_requiredAction,
    dueDate=p_dueDate, notes=p_notes
WHERE cveID=p_cveID;
ELSE
INSERT INTO knownExploited (cveID, vendorProject, product, vulnerabilityName,
                            dateAdded, shortDescription, requiredAction, dueDate, notes)
VALUES (p_cveID, p_vendorProject, p_product, p_vulnerabilityName, p_dateAdded,
    p_shortDescription, p_requiredAction, p_dueDate, p_notes);
END IF;
END
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON PROCEDURE public.merge_knownexploited(VARCHAR(20), VARCHAR(255), VARCHAR(255), VARCHAR(500), VARCHAR(10), VARCHAR(2000), VARCHAR(1000), VARCHAR(10), VARCHAR(2000)) TO dcuser;

CREATE FUNCTION update_vulnerability (
    IN p_cveId VARCHAR(20), IN p_description VARCHAR(8000), IN p_v2Severity VARCHAR(20), 
    IN p_v2ExploitabilityScore DECIMAL(3,1), IN p_v2ImpactScore DECIMAL(3,1), IN p_v2AcInsufInfo BOOLEAN, 
    IN p_v2ObtainAllPrivilege BOOLEAN, IN p_v2ObtainUserPrivilege BOOLEAN, IN p_v2ObtainOtherPrivilege BOOLEAN, 
    IN p_v2UserInteractionRequired BOOLEAN, IN p_v2Score DECIMAL(3,1), IN p_v2AccessVector VARCHAR(20), 
    IN p_v2AccessComplexity VARCHAR(20), IN p_v2Authentication VARCHAR(20), IN p_v2ConfidentialityImpact VARCHAR(20), 
    IN p_v2IntegrityImpact VARCHAR(20), IN p_v2AvailabilityImpact VARCHAR(20), IN p_v2Version VARCHAR(5),
    IN p_v3ExploitabilityScore DECIMAL(3,1), IN p_v3ImpactScore DECIMAL(3,1), IN p_v3AttackVector VARCHAR(20), 
    IN p_v3AttackComplexity VARCHAR(20), IN p_v3PrivilegesRequired VARCHAR(20), IN p_v3UserInteraction VARCHAR(20), 
    IN p_v3Scope VARCHAR(20), IN p_v3ConfidentialityImpact VARCHAR(20), IN p_v3IntegrityImpact VARCHAR(20), 
    IN p_v3AvailabilityImpact VARCHAR(20), IN p_v3BaseScore DECIMAL(3,1), IN p_v3BaseSeverity VARCHAR(20), 
    IN p_v3Version VARCHAR(5), IN p_v4version VARCHAR(5), IN p_v4attackVector VARCHAR(15), IN p_v4attackComplexity VARCHAR(15), 
    IN p_v4attackRequirements VARCHAR(15), IN p_v4privilegesRequired VARCHAR(15), IN p_v4userInteraction VARCHAR(15), 
    IN p_v4vulnConfidentialityImpact VARCHAR(15), IN p_v4vulnIntegrityImpact VARCHAR(15), IN p_v4vulnAvailabilityImpact VARCHAR(15), 
    IN p_v4subConfidentialityImpact VARCHAR(15), IN p_v4subIntegrityImpact VARCHAR(15), IN p_v4subAvailabilityImpact VARCHAR(15), 
    IN p_v4exploitMaturity VARCHAR(20), IN p_v4confidentialityRequirement VARCHAR(15), IN p_v4integrityRequirement VARCHAR(15), 
    IN p_v4availabilityRequirement VARCHAR(15), IN p_v4modifiedAttackVector VARCHAR(15), IN p_v4modifiedAttackComplexity VARCHAR(15), 
    IN p_v4modifiedAttackRequirements VARCHAR(15), IN p_v4modifiedPrivilegesRequired VARCHAR(15), IN p_v4modifiedUserInteraction VARCHAR(15), 
    IN p_v4modifiedVulnConfidentialityImpact VARCHAR(15), IN p_v4modifiedVulnIntegrityImpact VARCHAR(15), 
    IN p_v4modifiedVulnAvailabilityImpact VARCHAR(15), IN p_v4modifiedSubConfidentialityImpact VARCHAR(15), 
    IN p_v4modifiedSubIntegrityImpact VARCHAR(15), IN p_v4modifiedSubAvailabilityImpact VARCHAR(15), IN p_v4safety VARCHAR(15), 
    IN p_v4automatable VARCHAR(15), IN p_v4recovery VARCHAR(15), IN p_v4valueDensity VARCHAR(15), IN p_v4vulnerabilityResponseEffort VARCHAR(15), 
    IN p_v4providerUrgency VARCHAR(15), IN p_v4baseScore DECIMAL(3,1), IN p_v4baseSeverity VARCHAR(15), IN p_v4threatScore DECIMAL(3,1), 
    IN p_v4threatSeverity VARCHAR(15), IN p_v4environmentalScore DECIMAL(3,1), IN p_v4environmentalSeverity VARCHAR(15),
    IN p_v4source VARCHAR(50), IN p_v4type VARCHAR(15))
RETURNS TABLE (vulnerabilityId INT)
AS $$
DECLARE vulnerabilityId integer := 0;
BEGIN
SELECT vulnerability.id INTO vulnerabilityId FROM vulnerability WHERE cve=p_cveId;

IF vulnerabilityId > 0 THEN
    DELETE FROM reference WHERE cveid = vulnerabilityId;
    DELETE FROM software WHERE cveid = vulnerabilityId;
    DELETE FROM cweEntry WHERE cveid = vulnerabilityId;
    UPDATE vulnerability SET description=p_description,
        v2Severity=p_v2Severity, v2ExploitabilityScore=p_v2ExploitabilityScore, v2ImpactScore=p_v2ImpactScore, 
        v2AcInsufInfo=p_v2AcInsufInfo, v2ObtainAllPrivilege=p_v2ObtainAllPrivilege,
        v2ObtainUserPrivilege=p_v2ObtainUserPrivilege, v2ObtainOtherPrivilege=p_v2ObtainOtherPrivilege, 
        v2UserInteractionRequired=p_v2UserInteractionRequired, v2Score=p_v2Score, v2AccessVector=p_v2AccessVector, 
        v2AccessComplexity=p_v2AccessComplexity, v2Authentication=p_v2Authentication, v2ConfidentialityImpact=p_v2ConfidentialityImpact, 
        v2IntegrityImpact=p_v2IntegrityImpact, v2AvailabilityImpact=p_v2AvailabilityImpact, v2Version=p_v2Version, 
        v3ExploitabilityScore=p_v3ExploitabilityScore, v3ImpactScore=p_v3ImpactScore, v3AttackVector=p_v3AttackVector, 
        v3AttackComplexity=p_v3AttackComplexity, v3PrivilegesRequired=p_v3PrivilegesRequired, v3UserInteraction=p_v3UserInteraction, 
        v3Scope=p_v3Scope, v3ConfidentialityImpact=p_v3ConfidentialityImpact, v3IntegrityImpact=p_v3IntegrityImpact, 
        v3AvailabilityImpact=p_v3AvailabilityImpact, v3BaseScore=p_v3BaseScore, v3BaseSeverity=p_v3BaseSeverity, v3Version=p_v3Version,
        v4version=p_v4version, v4attackVector=p_v4attackVector, v4attackComplexity=p_v4attackComplexity, 
        v4attackRequirements=p_v4attackRequirements, v4privilegesRequired=p_v4privilegesRequired, 
        v4userInteraction=p_v4userInteraction, v4vulnConfidentialityImpact=p_v4vulnConfidentialityImpact, 
        v4vulnIntegrityImpact=p_v4vulnIntegrityImpact, v4vulnAvailabilityImpact=p_v4vulnAvailabilityImpact, 
        v4subConfidentialityImpact=p_v4subConfidentialityImpact, v4subIntegrityImpact=p_v4subIntegrityImpact, 
        v4subAvailabilityImpact=p_v4subAvailabilityImpact, v4exploitMaturity=p_v4exploitMaturity, 
        v4confidentialityRequirement=p_v4confidentialityRequirement, v4integrityRequirement=p_v4integrityRequirement, 
        v4availabilityRequirement=p_v4availabilityRequirement, v4modifiedAttackVector=p_v4modifiedAttackVector, 
        v4modifiedAttackComplexity=p_v4modifiedAttackComplexity, v4modifiedAttackRequirements=p_v4modifiedAttackRequirements, 
        v4modifiedPrivilegesRequired=p_v4modifiedPrivilegesRequired, v4modifiedUserInteraction=p_v4modifiedUserInteraction, 
        v4modifiedVulnConfidentialityImpact=p_v4modifiedVulnConfidentialityImpact, v4modifiedVulnIntegrityImpact=p_v4modifiedVulnIntegrityImpact, 
        v4modifiedVulnAvailabilityImpact=p_v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact=p_v4modifiedSubConfidentialityImpact, 
        v4modifiedSubIntegrityImpact=p_v4modifiedSubIntegrityImpact, v4modifiedSubAvailabilityImpact=p_v4modifiedSubAvailabilityImpact, 
        v4safety=p_v4safety, v4automatable=p_v4automatable, v4recovery=p_v4recovery, v4valueDensity=p_v4valueDensity, 
        v4vulnerabilityResponseEffort=p_v4vulnerabilityResponseEffort, v4providerUrgency=p_v4providerUrgency, 
        v4baseScore=p_v4baseScore, v4baseSeverity=p_v4baseSeverity, v4threatScore=p_v4threatScore, 
        v4threatSeverity=p_v4threatSeverity, v4environmentalScore=p_v4environmentalScore, v4environmentalSeverity=p_v4environmentalSeverity,
        v4source=p_v4source, v4type=p_v4type
    WHERE id=vulnerabilityId;
ELSE
    INSERT INTO vulnerability (cve, description, 
        v2Severity, v2ExploitabilityScore, 
        v2ImpactScore, v2AcInsufInfo, v2ObtainAllPrivilege, 
        v2ObtainUserPrivilege, v2ObtainOtherPrivilege, v2UserInteractionRequired, 
        v2Score, v2AccessVector, v2AccessComplexity, 
        v2Authentication, v2ConfidentialityImpact, v2IntegrityImpact, 
        v2AvailabilityImpact, v2Version, v3ExploitabilityScore, 
        v3ImpactScore, v3AttackVector, v3AttackComplexity, 
        v3PrivilegesRequired, v3UserInteraction, v3Scope, 
        v3ConfidentialityImpact, v3IntegrityImpact, v3AvailabilityImpact, 
        v3BaseScore, v3BaseSeverity, v3Version, v4version, 
        v4attackVector, v4attackComplexity, v4attackRequirements, v4privilegesRequired, 
        v4userInteraction, v4vulnConfidentialityImpact, v4vulnIntegrityImpact, v4vulnAvailabilityImpact, 
        v4subConfidentialityImpact, v4subIntegrityImpact, v4subAvailabilityImpact, v4exploitMaturity, 
        v4confidentialityRequirement, v4integrityRequirement, v4availabilityRequirement, 
        v4modifiedAttackVector, v4modifiedAttackComplexity, v4modifiedAttackRequirements, 
        v4modifiedPrivilegesRequired, v4modifiedUserInteraction, v4modifiedVulnConfidentialityImpact, 
        v4modifiedVulnIntegrityImpact, v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact, 
        v4modifiedSubIntegrityImpact, v4modifiedSubAvailabilityImpact, v4safety, v4automatable, v4recovery, 
        v4valueDensity, v4vulnerabilityResponseEffort, v4providerUrgency, v4baseScore, v4baseSeverity, 
        v4threatScore, v4threatSeverity, v4environmentalScore, v4environmentalSeverity, v4source, v4type) 
        VALUES (p_cveId, p_description, 
        p_v2Severity, p_v2ExploitabilityScore, 
        p_v2ImpactScore, p_v2AcInsufInfo, p_v2ObtainAllPrivilege, 
        p_v2ObtainUserPrivilege, p_v2ObtainOtherPrivilege, p_v2UserInteractionRequired, 
        p_v2Score, p_v2AccessVector, p_v2AccessComplexity, 
        p_v2Authentication, p_v2ConfidentialityImpact, p_v2IntegrityImpact, 
        p_v2AvailabilityImpact, p_v2Version, p_v3ExploitabilityScore, 
        p_v3ImpactScore, p_v3AttackVector, p_v3AttackComplexity, 
        p_v3PrivilegesRequired, p_v3UserInteraction, p_v3Scope, 
        p_v3ConfidentialityImpact, p_v3IntegrityImpact, p_v3AvailabilityImpact, 
        p_v3BaseScore, p_v3BaseSeverity, p_v3Version, p_v4version, 
        p_v4attackVector, p_v4attackComplexity, p_v4attackRequirements, p_v4privilegesRequired, 
        p_v4userInteraction, p_v4vulnConfidentialityImpact, p_v4vulnIntegrityImpact, p_v4vulnAvailabilityImpact, 
        p_v4subConfidentialityImpact, p_v4subIntegrityImpact, p_v4subAvailabilityImpact, p_v4exploitMaturity, 
        p_v4confidentialityRequirement, p_v4integrityRequirement, p_v4availabilityRequirement, 
        p_v4modifiedAttackVector, p_v4modifiedAttackComplexity, p_v4modifiedAttackRequirements, 
        p_v4modifiedPrivilegesRequired, p_v4modifiedUserInteraction, p_v4modifiedVulnConfidentialityImpact, 
        p_v4modifiedVulnIntegrityImpact, p_v4modifiedVulnAvailabilityImpact, p_v4modifiedSubConfidentialityImpact, 
        p_v4modifiedSubIntegrityImpact, p_v4modifiedSubAvailabilityImpact, p_v4safety, p_v4automatable, p_v4recovery, 
        p_v4valueDensity, p_v4vulnerabilityResponseEffort, p_v4providerUrgency, p_v4baseScore, p_v4baseSeverity, 
        p_v4threatScore, p_v4threatSeverity, p_v4environmentalScore, p_v4environmentalSeverity, p_v4source, p_v4type);
        
    SELECT lastval() INTO vulnerabilityId;
END IF;

RETURN QUERY SELECT vulnerabilityId;
END;
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON FUNCTION public.update_vulnerability(VARCHAR(20), VARCHAR(8000), 
    VARCHAR(20), DECIMAL(3,1), DECIMAL(3,1), BOOLEAN, BOOLEAN, BOOLEAN, BOOLEAN, 
    BOOLEAN, DECIMAL(3,1), VARCHAR(20), VARCHAR(20), VARCHAR(20), VARCHAR(20), 
    VARCHAR(20), VARCHAR(20), VARCHAR(5), DECIMAL(3,1), DECIMAL(3,1), VARCHAR(20), 
    VARCHAR(20), VARCHAR(20), VARCHAR(20), VARCHAR(20), VARCHAR(20), VARCHAR(20), 
    VARCHAR(20), DECIMAL(3,1), VARCHAR(20), VARCHAR(5), VARCHAR(5), VARCHAR(15), 
    VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), 
    VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(20), VARCHAR(15), 
    VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), 
    VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), 
    VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), VARCHAR(15), 
    VARCHAR(15), DECIMAL(3,1), VARCHAR(15), DECIMAL(3,1), VARCHAR(15), DECIMAL(3,1), 
    VARCHAR(15), VARCHAR(50), VARCHAR(15)) TO dcuser;

CREATE FUNCTION insert_software (
    IN p_vulnerabilityId INT, IN p_part CHAR(1), IN p_vendor VARCHAR(255), IN p_product VARCHAR(255),
    IN p_version VARCHAR(255), IN p_update_version VARCHAR(255), IN p_edition VARCHAR(255), IN p_lang VARCHAR(20),
    IN p_sw_edition VARCHAR(255), IN p_target_sw VARCHAR(255), IN p_target_hw VARCHAR(255), IN p_other VARCHAR(255), 
    IN p_ecosystem VARCHAR(255), IN p_versionEndExcluding VARCHAR(100), IN p_versionEndIncluding VARCHAR(100), 
    IN p_versionStartExcluding VARCHAR(100), IN p_versionStartIncluding VARCHAR(100), IN p_vulnerable BOOLEAN)
RETURNS void
AS $$
DECLARE 
cpeId INT := 0; 
currentEcosystem VARCHAR(255);
BEGIN

    SELECT id, ecosystem 
    INTO cpeId, currentEcosystem
    FROM cpeEntry WHERE part=p_part AND vendor=p_vendor AND product=p_product
        AND version=p_version AND update_version=p_update_version AND edition=p_edition 
        AND lang=p_lang AND sw_edition=p_sw_edition AND target_sw=p_target_sw 
        AND target_hw=p_target_hw AND other=p_other;

    IF cpeId > 0 THEN
        IF currentEcosystem IS NULL AND p_ecosystem IS NOT NULL THEN
            UPDATE cpeEntry SET ecosystem=p_ecosystem WHERE id=cpeId;
        END IF;
    ELSE
        INSERT INTO cpeEntry (part, vendor, product, version, update_version, 
            edition, lang, sw_edition, target_sw, target_hw, other, ecosystem) 
        VALUES (p_part, p_vendor, p_product, p_version, p_update_version, 
                p_edition, p_lang, p_sw_edition, p_target_sw, p_target_hw, p_other, p_ecosystem);
        SELECT lastval() INTO cpeId;
    END IF;

    INSERT INTO software (cveid, cpeEntryId, versionEndExcluding, versionEndIncluding,
            versionStartExcluding, versionStartIncluding, vulnerable) 
    VALUES (p_vulnerabilityId, cpeId, p_versionEndExcluding, p_versionEndIncluding,
            p_versionStartExcluding, p_versionStartIncluding, p_vulnerable);

END;
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON FUNCTION public.insert_software (INT, CHAR(1), VARCHAR(255), 
    VARCHAR(255), VARCHAR(255), VARCHAR(255), VARCHAR(255), VARCHAR(20), 
    VARCHAR(255), VARCHAR(255), VARCHAR(255), VARCHAR(255), VARCHAR(255), 
    VARCHAR(50), VARCHAR(50), VARCHAR(50), VARCHAR(50), BOOLEAN) TO dcuser;



INSERT INTO properties(id,value) VALUES ('version','5.5');
