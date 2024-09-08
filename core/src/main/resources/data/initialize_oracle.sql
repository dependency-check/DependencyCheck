-- DROP USER dcuser CASCADE;
-- CREATE USER dcuser IDENTIFIED BY "DC-Pass1337!";
-- GRANT UNLIMITED TABLESPACE TO dcuser;
-- GRANT CREATE SESSION to dcuser;

-- ALTER SESSION SET CURRENT_SCHEMA=dcuser;



BEGIN
  EXECUTE IMMEDIATE 'DROP SEQUENCE vulnerability_seq';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -2289 THEN
      RAISE;
    END IF;
END;
/

BEGIN
  EXECUTE IMMEDIATE 'DROP SEQUENCE cpeEntry_seq';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -2289 THEN
      RAISE;
    END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE software CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cpeEntry CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE reference CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE vulnerability CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE properties CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cweEntry CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE cpeEcosystemCache CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE knownExploited CASCADE CONSTRAINTS';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/


CREATE TABLE vulnerability (id INT NOT NULL PRIMARY KEY, cve VARCHAR(20) UNIQUE,
    description CLOB,
    v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1),
    v2ImpactScore DECIMAL(3,1), v2AcInsufInfo NUMBER(1), v2ObtainAllPrivilege NUMBER(1),
    v2ObtainUserPrivilege NUMBER(1), v2ObtainOtherPrivilege NUMBER(1), v2UserInteractionRequired NUMBER(1),
    v2Score DECIMAL(3,1), v2AccessVector VARCHAR(20), v2AccessComplexity VARCHAR(20),
    v2Authentication VARCHAR(20), v2ConfidentialityImpact VARCHAR(20), v2IntegrityImpact VARCHAR(20),
    v2AvailabilityImpact VARCHAR(20), v2Version VARCHAR(5),
    v3ExploitabilityScore DECIMAL(3,1),
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

CREATE TABLE cpeEntry (id INT NOT NULL PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(100), versionEndIncluding VARCHAR(100), 
                       versionStartExcluding VARCHAR(100), versionStartIncluding VARCHAR(100), vulnerable number(1)
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


-- CREATE INDEX idxCwe ON cweEntry(cveid); -- PK automatically receives index
-- CREATE INDEX idxVulnerability ON vulnerability(cve); -- PK automatically receives index
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

CREATE UNIQUE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));

CREATE SEQUENCE cpeEntry_seq;
CREATE SEQUENCE vulnerability_seq;

CREATE OR REPLACE TRIGGER VULNERABILITY_TRG
BEFORE INSERT
ON vulnerability
REFERENCING NEW AS New OLD AS Old
FOR EACH ROW
BEGIN
  :new.ID := vulnerability_seq.nextval;
END VULNERABILITY_TRG;
/

CREATE OR REPLACE TRIGGER CPEENTRY_TRG
BEFORE INSERT
ON cpeEntry
REFERENCING NEW AS New OLD AS Old
FOR EACH ROW
BEGIN
  :new.ID := cpeEntry_seq.nextval;
END CPEENTRY_TRG;
/

CREATE OR REPLACE PROCEDURE save_property(prop IN properties.id%type, val IN properties.value%type) AS
BEGIN
    INSERT INTO properties (id, value) VALUES (prop, val);
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        UPDATE properties SET value=val WHERE id=prop;
END;
/

GRANT EXECUTE ON save_property TO dcuser;


CREATE OR REPLACE PROCEDURE merge_ecosystem(p_vendor IN cpeEcosystemCache.vendor%type, p_product IN cpeEcosystemCache.product%type, p_ecosystem IN cpeEcosystemCache.ecosystem%type) AS
BEGIN
    INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES (p_vendor, p_product, p_ecosystem);
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        UPDATE cpeEcosystemCache SET ecosystem=p_ecosystem WHERE product=p_product AND vendor=p_vendor;
END;
/

GRANT EXECUTE ON merge_ecosystem TO dcuser;

CREATE OR REPLACE PROCEDURE merge_knownexploited(
    p_cveID IN knownExploited.cveID%type,
    p_vendorProject IN knownExploited.vendorProject%type,
    p_product IN knownExploited.product%type,
    p_vulnerabilityName IN knownExploited.vulnerabilityName%type,
    p_dateAdded IN knownExploited.dateAdded%type,
    p_shortDescription IN knownExploited.shortDescription%type,
    p_requiredAction IN knownExploited.requiredAction%type,
    p_dueDate IN knownExploited.dueDate%type,
    p_notes IN knownExploited.notes%type)
AS
BEGIN
    INSERT INTO knownExploited (cveID, vendorProject, product, vulnerabilityName,
            dateAdded, shortDescription, requiredAction, dueDate, notes)
    VALUES (p_cveID, p_vendorProject, p_product, p_vulnerabilityName, p_dateAdded,
            p_shortDescription, p_requiredAction, p_dueDate, p_notes);
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        UPDATE knownExploited
        SET vendorProject=p_vendorProject, product=p_product, vulnerabilityName=p_vulnerabilityName, 
            dateAdded=p_dateAdded, shortDescription=p_shortDescription, requiredAction=p_requiredAction, 
            dueDate=p_dueDate, notes=p_notes
        WHERE cveID=p_cveID;
END;
/

GRANT EXECUTE ON merge_knownexploited TO dcuser;

CREATE OR REPLACE PROCEDURE update_vulnerability(p_cveId IN vulnerability.cve%type,
                                      p_description IN vulnerability.description%type,
                                      p_v2Severity IN vulnerability.v2Severity%type,
                                      p_v2ExploitabilityScore IN vulnerability.v2ExploitabilityScore%type,
                                      p_v2ImpactScore IN vulnerability.v2ImpactScore%type,
                                      p_v2AcInsufInfo IN vulnerability.v2AcInsufInfo%type,
                                      p_v2ObtainAllPrivilege IN vulnerability.v2ObtainAllPrivilege%type,
                                      p_v2ObtainUserPrivilege IN vulnerability.v2ObtainUserPrivilege%type,
                                      p_v2ObtainOtherPrivilege IN vulnerability.v2ObtainOtherPrivilege%type,
                                      p_v2UserInteractionRequired IN vulnerability.v2UserInteractionRequired%type,
                                      p_v2Score IN vulnerability.v2Score%type,
                                      p_v2AccessVector IN vulnerability.v2AccessVector%type,
                                      p_v2AccessComplexity IN vulnerability.v2AccessComplexity%type,
                                      p_v2Authentication IN vulnerability.v2Authentication%type,
                                      p_v2ConfidentialityImpact IN vulnerability.v2ConfidentialityImpact%type,
                                      p_v2IntegrityImpact IN vulnerability.v2IntegrityImpact%type,
                                      p_v2AvailabilityImpact IN vulnerability.v2AvailabilityImpact%type,
                                      p_v2Version IN vulnerability.v2Version%type,
                                      p_v3ExploitabilityScore IN vulnerability.v3ExploitabilityScore%type,
                                      p_v3ImpactScore IN vulnerability.v3ImpactScore%type,
                                      p_v3AttackVector IN vulnerability.v3AttackVector%type,
                                      p_v3AttackComplexity IN vulnerability.v3AttackComplexity%type,
                                      p_v3PrivilegesRequired IN vulnerability.v3PrivilegesRequired%type,
                                      p_v3UserInteraction IN vulnerability.v3UserInteraction%type,
                                      p_v3Scope IN vulnerability.v3Scope%type,
                                      p_v3ConfidentialityImpact IN vulnerability.v3ConfidentialityImpact%type,
                                      p_v3IntegrityImpact IN vulnerability.v3IntegrityImpact%type,
                                      p_v3AvailabilityImpact IN vulnerability.v3AvailabilityImpact%type,
                                      p_v3BaseScore IN vulnerability.v3BaseScore%type,
                                      p_v3BaseSeverity IN vulnerability.v3BaseSeverity%type,
                                      p_v3Version IN vulnerability.v3Version%type,
                                      p_v4version IN vulnerability.v4version%type, 
                                      p_v4attackVector IN vulnerability.v4attackVector%type, 
                                      p_v4attackComplexity IN vulnerability.v4attackComplexity%type, 
                                      p_v4attackRequirements IN vulnerability.v4attackRequirements%type, 
                                      p_v4privilegesRequired IN vulnerability.v4privilegesRequired%type, 
                                      p_v4userInteraction IN vulnerability.v4userInteraction%type, 
                                      p_v4vulnConfidentialityImpact IN vulnerability.v4vulnConfidentialityImpact%type, 
                                      p_v4vulnIntegrityImpact IN vulnerability.v4vulnIntegrityImpact%type, 
                                      p_v4vulnAvailabilityImpact IN vulnerability.v4vulnAvailabilityImpact%type, 
                                      p_v4subConfidentialityImpact IN vulnerability.v4subConfidentialityImpact%type, 
                                      p_v4subIntegrityImpact IN vulnerability.v4subIntegrityImpact%type, 
                                      p_v4subAvailabilityImpact IN vulnerability.v4subAvailabilityImpact%type, 
                                      p_v4exploitMaturity IN vulnerability.v4exploitMaturity%type, 
                                      p_v4confidentialityRequirement IN vulnerability.v4confidentialityRequirement%type, 
                                      p_v4integrityRequirement IN vulnerability.v4integrityRequirement%type, 
                                      p_v4availabilityRequirement IN vulnerability.v4availabilityRequirement%type, 
                                      p_v4modifiedAttackVector IN vulnerability.v4modifiedAttackVector%type, 
                                      p_v4modifiedAttackComplexity IN vulnerability.v4modifiedAttackComplexity%type, 
                                      p_v4modifiedAttackRequirements IN vulnerability.v4modifiedAttackRequirements%type, 
                                      p_v4modifiedPrivilegesRequired IN vulnerability.v4modifiedPrivilegesRequired%type, 
                                      p_v4modifiedUserInteraction IN vulnerability.v4modifiedUserInteraction%type, 
                                      p_v4modifiedVulnConfidentialityImpact IN vulnerability.v4modifiedVulnConfidentialityImpact%type, 
                                      p_v4modifiedVulnIntegrityImpact IN vulnerability.v4modifiedVulnIntegrityImpact%type, 
                                      p_v4modifiedVulnAvailabilityImpact IN vulnerability.v4modifiedVulnAvailabilityImpact%type, 
                                      p_v4modifiedSubConfidentialityImpact IN vulnerability.v4modifiedSubConfidentialityImpact%type, 
                                      p_v4modifiedSubIntegrityImpact IN vulnerability.v4modifiedSubIntegrityImpact%type, 
                                      p_v4modifiedSubAvailabilityImpact IN vulnerability.v4modifiedSubAvailabilityImpact%type, 
                                      p_v4safety IN vulnerability.v4safety%type, 
                                      p_v4automatable IN vulnerability.v4automatable%type, 
                                      p_v4recovery IN vulnerability.v4recovery%type, 
                                      p_v4valueDensity IN vulnerability.v4valueDensity%type, 
                                      p_v4vulnerabilityResponseEffort IN vulnerability.v4vulnerabilityResponseEffort%type, 
                                      p_v4providerUrgency IN vulnerability.v4providerUrgency%type, 
                                      p_v4baseScore IN vulnerability.v4baseScore%type, 
                                      p_v4baseSeverity IN vulnerability.v4baseSeverity%type, 
                                      p_v4threatScore IN vulnerability.v4threatScore%type, 
                                      p_v4threatSeverity IN vulnerability.v4threatSeverity%type, 
                                      p_v4environmentalScore IN vulnerability.v4environmentalScore%type, 
                                      p_v4environmentalSeverity IN vulnerability.v4environmentalSeverity%type, 
                                      p_v4source IN vulnerability.v4source%type, 
                                      p_v4type IN vulnerability.v4type%type, 
                                      vulnerabilityId OUT vulnerability.id%type)
                                       AS
BEGIN
    BEGIN
        SELECT id into vulnerabilityId FROM vulnerability WHERE cve = p_cveId;
        DELETE FROM reference WHERE cveid = vulnerabilityId;
        DELETE FROM software WHERE cveid = vulnerabilityId;
        DELETE FROM cweEntry WHERE cveid = vulnerabilityId;
        UPDATE vulnerability
        SET description=p_description,
            v2Severity=p_v2Severity,
            v2ExploitabilityScore=p_v2ExploitabilityScore,
            v2ImpactScore=p_v2ImpactScore,
            v2AcInsufInfo=p_v2AcInsufInfo,
            v2ObtainAllPrivilege=p_v2ObtainAllPrivilege,
            v2ObtainUserPrivilege=p_v2ObtainUserPrivilege,
            v2ObtainOtherPrivilege=p_v2ObtainOtherPrivilege,
            v2UserInteractionRequired=p_v2UserInteractionRequired,
            v2Score=p_v2Score,
            v2AccessVector=p_v2AccessVector,
            v2AccessComplexity=p_v2AccessComplexity,
            v2Authentication=p_v2Authentication,
            v2ConfidentialityImpact=p_v2ConfidentialityImpact,
            v2IntegrityImpact=p_v2IntegrityImpact,
            v2AvailabilityImpact=p_v2AvailabilityImpact,
            v2Version=p_v2Version,
            v3ExploitabilityScore=p_v3ExploitabilityScore,
            v3ImpactScore=p_v3ImpactScore,
            v3AttackVector=p_v3AttackVector,
            v3AttackComplexity=p_v3AttackComplexity,
            v3PrivilegesRequired=p_v3PrivilegesRequired,
            v3UserInteraction=p_v3UserInteraction,
            v3Scope=p_v3Scope,
            v3ConfidentialityImpact=p_v3ConfidentialityImpact,
            v3IntegrityImpact=p_v3IntegrityImpact,
            v3AvailabilityImpact=p_v3AvailabilityImpact,
            v3BaseScore=p_v3BaseScore,
            v3BaseSeverity=p_v3BaseSeverity,
            v3Version=p_v3Version,
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
        WHERE id = vulnerabilityId;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
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
                    p_v4threatScore, p_v4threatSeverity, p_v4environmentalScore, p_v4environmentalSeverity, p_v4source, p_v4type)
            RETURNING id INTO vulnerabilityId;
        WHEN OTHERS THEN
            RAISE;
    END;
END;
/

GRANT EXECUTE ON update_vulnerability TO dcuser;

CREATE OR REPLACE PROCEDURE insert_software(p_vulnerabilityId IN software.cveid%type,
                                 p_part IN cpeEntry.part%type,
                                 p_vendor IN cpeEntry.vendor%type,
                                 p_product IN cpeEntry.product%type,
                                 p_version IN cpeEntry.version%type,
                                 p_update_version IN cpeEntry.update_version%type,
                                 p_edition IN cpeEntry.edition%type,
                                 p_lang IN cpeEntry.lang%type,
                                 p_sw_edition IN cpeEntry.sw_edition%type,
                                 p_target_sw IN cpeEntry.target_sw%type,
                                 p_target_hw IN cpeEntry.target_hw%type,
                                 p_other IN cpeEntry.other%type,
                                 p_ecosystem IN cpeEntry.ecosystem%type,
                                 p_versionEndExcluding IN software.versionEndExcluding%type,
                                 p_versionEndIncluding IN software.versionEndIncluding%type,
                                 p_versionStartExcluding IN software.versionStartExcluding%type,
                                 p_versionStartIncluding IN software.versionStartIncluding%type,
                                 p_vulnerable IN software.vulnerable%type) AS
    cpeId cpeEntry.id%type;
    currentEcosystem cpeEntry.ecosystem%type;
BEGIN
    BEGIN
        SELECT id, ecosystem
        INTO cpeId, currentEcosystem
        FROM cpeEntry
        WHERE part = p_part
          AND vendor = p_vendor
          AND product = p_product
          AND version = p_version
          AND update_version = p_update_version
          AND edition = p_edition
          AND lang = p_lang
          AND sw_edition = p_sw_edition
          AND target_sw = p_target_sw
          AND target_hw = p_target_hw
          AND other = p_other;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
           cpeId := 0;
           currentEcosystem := NULL;
        WHEN OTHERS THEN
           RAISE;
    END;

    IF cpeId > 0 THEN
        IF currentEcosystem IS NULL AND p_ecosystem IS NOT NULL THEN
            UPDATE cpeEntry SET ecosystem=p_ecosystem WHERE id = cpeId;
        END IF;
    ELSE
        INSERT INTO cpeEntry (part,
                              vendor,
                              product,
                              version,
                              update_version,
                              edition,
                              lang,
                              sw_edition,
                              target_sw,
                              target_hw,
                              other,
                              ecosystem)
        VALUES (p_part,
                p_vendor,
                p_product,
                p_version,
                p_update_version,
                p_edition,
                p_lang,
                p_sw_edition,
                p_target_sw,
                p_target_hw,
                p_other,
                p_ecosystem)
        RETURNING id INTO cpeId;
    END IF;

    INSERT INTO software (cveid,
                          cpeEntryId,
                          versionEndExcluding,
                          versionEndIncluding,
                          versionStartExcluding,
                          versionStartIncluding,
                          vulnerable)
    VALUES (p_vulnerabilityId,
            cpeId,
            p_versionEndExcluding,
            p_versionEndIncluding,
            p_versionStartExcluding,
            p_versionStartIncluding,
            p_vulnerable);

END;
/

GRANT EXECUTE ON insert_software TO dcuser;

CREATE OR REPLACE VIEW v_update_ecosystems AS
    SELECT e.ecosystem AS entryEco, c.ecosystem AS cachedEco
    FROM cpeEntry e INNER JOIN cpeEcosystemCache c
    ON c.vendor=e.vendor
        AND c.product=e.product;

INSERT INTO properties(id,value) VALUES ('version','5.5');
