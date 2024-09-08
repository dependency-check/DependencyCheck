--CREATE database dependencycheck;
USE dependencycheck;
GO

if exists (SELECT 1 FROM sysobjects WHERE name='software' AND xtype='U')
    drop table software;
if exists (SELECT 1 FROM sysobjects WHERE name='cpeEntry' AND xtype='U')
    drop table cpeEntry;
if exists (SELECT 1 FROM sysobjects WHERE name='reference' AND xtype='U')
    drop table reference;
if exists (SELECT 1 FROM sysobjects WHERE name='properties' AND xtype='U')
    drop table properties;
if exists (SELECT 1 FROM sysobjects WHERE name='cweEntry' AND xtype='U')
    drop table cweEntry;
if exists (SELECT 1 FROM sysobjects WHERE name='cpeEcosystemCache' AND xtype='U')
    drop table cpeEcosystemCache;
if exists (SELECT 1 FROM sysobjects WHERE name='vulnerability' AND xtype='U')
    drop table vulnerability;
if exists (SELECT 1 FROM sysobjects WHERE name='save_property' AND xtype='P')
    drop procedure save_property;
if exists (SELECT 1 FROM sysobjects WHERE name='merge_ecosystem' AND xtype='P')
    drop procedure merge_ecosystem;
if exists (SELECT 1 FROM sysobjects WHERE name='update_vulnerability' AND xtype='P')
    drop procedure update_vulnerability;
if exists (SELECT 1 FROM sysobjects WHERE name='insert_software' AND xtype='P')
    drop procedure insert_software;    
if exists (SELECT 1 FROM sysobjects WHERE name='knownExploited' AND xtype='U')
    drop table knownExploited;
if exists (SELECT 1 FROM sysobjects WHERE name='merge_knownexploited' AND xtype='P')
    drop procedure merge_knownexploited;    

CREATE TABLE vulnerability (id int identity(1,1) PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1), 
        v2ImpactScore DECIMAL(3,1), v2AcInsufInfo BIT, v2ObtainAllPrivilege BIT, 
        v2ObtainUserPrivilege BIT, v2ObtainOtherPrivilege BIT, v2UserInteractionRequired BIT, 
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
	CONSTRAINT FK_Reference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT identity(1,1) PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
    version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
    target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(100), versionEndIncluding VARCHAR(100), 
                       versionStartExcluding VARCHAR(100), versionStartIncluding VARCHAR(100), vulnerable BIT
    , CONSTRAINT FK_SoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT FK_SoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20)
    , CONSTRAINT FK_CweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));
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
--CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

--on mssql we cannot index all columns due to key length issues
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version);
--, update_version, edition, lang, sw_edition, target_sw, target_hw, other);


GO

CREATE PROCEDURE save_property (@prop VARCHAR(50), @value VARCHAR(500))
AS
BEGIN
IF EXISTS(SELECT * FROM properties WHERE id=@prop)
    UPDATE properties SET value=@value WHERE id=@prop;
ELSE
    INSERT INTO properties (id, value) VALUES (@prop, @value);
END;

GO

CREATE PROCEDURE merge_ecosystem (@vendor VARCHAR(255), @product VARCHAR(255), @ecosystem varchar(255))
AS
BEGIN
IF EXISTS(SELECT * FROM cpeEcosystemCache WHERE vendor=@vendor AND product=@product)
    UPDATE cpeEcosystemCache SET ecosystem=@ecosystem WHERE vendor=@vendor AND product=@product;
ELSE
    INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES (@vendor, @product, @ecosystem);
END;

GO

CREATE PROCEDURE update_vulnerability (
    @cveId VARCHAR(20), @description VARCHAR(8000), @v2Severity VARCHAR(20), 
    @v2ExploitabilityScore DECIMAL(3,1), @v2ImpactScore DECIMAL(3,1), @v2AcInsufInfo BIT, 
    @v2ObtainAllPrivilege BIT, @v2ObtainUserPrivilege BIT, @v2ObtainOtherPrivilege BIT, 
    @v2UserInteractionRequired BIT, @v2Score DECIMAL(3,1), @v2AccessVector VARCHAR(20), 
    @v2AccessComplexity VARCHAR(20), @v2Authentication VARCHAR(20), @v2ConfidentialityImpact VARCHAR(20), 
    @v2IntegrityImpact VARCHAR(20), @v2AvailabilityImpact VARCHAR(20), @v2Version VARCHAR(5),
    @v3ExploitabilityScore DECIMAL(3,1), @v3ImpactScore DECIMAL(3,1), @v3AttackVector VARCHAR(20), 
    @v3AttackComplexity VARCHAR(20), @v3PrivilegesRequired VARCHAR(20), @v3UserInteraction VARCHAR(20), 
    @v3Scope VARCHAR(20), @v3ConfidentialityImpact VARCHAR(20), @v3IntegrityImpact VARCHAR(20), 
    @v3AvailabilityImpact VARCHAR(20), @v3BaseScore DECIMAL(3,1), @v3BaseSeverity VARCHAR(20), 
    @v3Version VARCHAR(5), @v4version VARCHAR(5), @v4attackVector VARCHAR(15), @v4attackComplexity VARCHAR(15), 
    @v4attackRequirements VARCHAR(15), @v4privilegesRequired VARCHAR(15), @v4userInteraction VARCHAR(15), 
    @v4vulnConfidentialityImpact VARCHAR(15), @v4vulnIntegrityImpact VARCHAR(15), @v4vulnAvailabilityImpact VARCHAR(15), 
    @v4subConfidentialityImpact VARCHAR(15), @v4subIntegrityImpact VARCHAR(15), @v4subAvailabilityImpact VARCHAR(15), 
    @v4exploitMaturity VARCHAR(20), @v4confidentialityRequirement VARCHAR(15), @v4integrityRequirement VARCHAR(15), 
    @v4availabilityRequirement VARCHAR(15), @v4modifiedAttackVector VARCHAR(15), @v4modifiedAttackComplexity VARCHAR(15), 
    @v4modifiedAttackRequirements VARCHAR(15), @v4modifiedPrivilegesRequired VARCHAR(15), @v4modifiedUserInteraction VARCHAR(15), 
    @v4modifiedVulnConfidentialityImpact VARCHAR(15), @v4modifiedVulnIntegrityImpact VARCHAR(15), 
    @v4modifiedVulnAvailabilityImpact VARCHAR(15), @v4modifiedSubConfidentialityImpact VARCHAR(15), 
    @v4modifiedSubIntegrityImpact VARCHAR(15), @v4modifiedSubAvailabilityImpact VARCHAR(15), @v4safety VARCHAR(15), 
    @v4automatable VARCHAR(15), @v4recovery VARCHAR(15), @v4valueDensity VARCHAR(15), @v4vulnerabilityResponseEffort VARCHAR(15), 
    @v4providerUrgency VARCHAR(15), @v4baseScore DECIMAL(3,1), @v4baseSeverity VARCHAR(15), @v4threatScore DECIMAL(3,1), 
    @v4threatSeverity VARCHAR(15), @v4environmentalScore DECIMAL(3,1), @v4environmentalSeverity VARCHAR(15),
    @v4source VARCHAR(15), @v4type VARCHAR(15)) AS
BEGIN
DECLARE @vulnerabilityId INT;

SELECT @vulnerabilityId=id FROM vulnerability WHERE cve=@cveId;

IF @vulnerabilityId > 0
BEGIN
    DELETE FROM reference WHERE cveid = @vulnerabilityId;
    DELETE FROM software WHERE cveid = @vulnerabilityId;
    DELETE FROM cweEntry WHERE cveid = @vulnerabilityId;
    UPDATE vulnerability SET description=@description,
        v2Severity=@v2Severity, v2ExploitabilityScore=@v2ExploitabilityScore, v2ImpactScore=@v2ImpactScore, 
        v2AcInsufInfo=@v2AcInsufInfo, v2ObtainAllPrivilege=@v2ObtainAllPrivilege,
        v2ObtainUserPrivilege=@v2ObtainUserPrivilege, v2ObtainOtherPrivilege=@v2ObtainOtherPrivilege, 
        v2UserInteractionRequired=@v2UserInteractionRequired, v2Score=@v2Score, v2AccessVector=@v2AccessVector, 
        v2AccessComplexity=@v2AccessComplexity, v2Authentication=@v2Authentication, v2ConfidentialityImpact=@v2ConfidentialityImpact, 
        v2IntegrityImpact=@v2IntegrityImpact, v2AvailabilityImpact=@v2AvailabilityImpact, v2Version=@v2Version, 
        v3ExploitabilityScore=@v3ExploitabilityScore, v3ImpactScore=@v3ImpactScore, v3AttackVector=@v3AttackVector, 
        v3AttackComplexity=@v3AttackComplexity, v3PrivilegesRequired=@v3PrivilegesRequired, v3UserInteraction=@v3UserInteraction, 
        v3Scope=@v3Scope, v3ConfidentialityImpact=@v3ConfidentialityImpact, v3IntegrityImpact=@v3IntegrityImpact, 
        v3AvailabilityImpact=@v3AvailabilityImpact, v3BaseScore=@v3BaseScore, v3BaseSeverity=@v3BaseSeverity, v3Version=@v3Version,
        v4version=@v4version, v4attackVector=@v4attackVector, v4attackComplexity=@v4attackComplexity, v4attackRequirements=@v4attackRequirements, 
        v4privilegesRequired=@v4privilegesRequired, v4userInteraction=@v4userInteraction, v4vulnConfidentialityImpact=@v4vulnConfidentialityImpact, 
        v4vulnIntegrityImpact=@v4vulnIntegrityImpact, v4vulnAvailabilityImpact=@v4vulnAvailabilityImpact, 
        v4subConfidentialityImpact=@v4subConfidentialityImpact, v4subIntegrityImpact=@v4subIntegrityImpact, 
        v4subAvailabilityImpact=@v4subAvailabilityImpact, v4exploitMaturity=@v4exploitMaturity, 
        v4confidentialityRequirement=@v4confidentialityRequirement, v4integrityRequirement=@v4integrityRequirement, 
        v4availabilityRequirement=@v4availabilityRequirement, v4modifiedAttackVector=@v4modifiedAttackVector, 
        v4modifiedAttackComplexity=@v4modifiedAttackComplexity, v4modifiedAttackRequirements=@v4modifiedAttackRequirements, 
        v4modifiedPrivilegesRequired=@v4modifiedPrivilegesRequired, v4modifiedUserInteraction=@v4modifiedUserInteraction, 
        v4modifiedVulnConfidentialityImpact=@v4modifiedVulnConfidentialityImpact, v4modifiedVulnIntegrityImpact=@v4modifiedVulnIntegrityImpact, 
        v4modifiedVulnAvailabilityImpact=@v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact=@v4modifiedSubConfidentialityImpact, 
        v4modifiedSubIntegrityImpact=@v4modifiedSubIntegrityImpact, v4modifiedSubAvailabilityImpact=@v4modifiedSubAvailabilityImpact, 
        v4safety=@v4safety, v4automatable=@v4automatable, v4recovery=@v4recovery, v4valueDensity=@v4valueDensity, 
        v4vulnerabilityResponseEffort=@v4vulnerabilityResponseEffort, v4providerUrgency=@v4providerUrgency, 
        v4baseScore=@v4baseScore, v4baseSeverity=@v4baseSeverity, v4threatScore=@v4threatScore, 
        v4threatSeverity=@v4threatSeverity, v4environmentalScore=@v4environmentalScore, 
        v4environmentalSeverity=@v4environmentalSeverity, v4source=@v4source, v4type=@v4type
    WHERE id=@vulnerabilityId;
END
ELSE
BEGIN
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
        v3BaseScore, v3BaseSeverity, v3Version, v4version, v4attackVector, 
        v4attackComplexity, v4attackRequirements, v4privilegesRequired, v4userInteraction, 
        v4vulnConfidentialityImpact, v4vulnIntegrityImpact, v4vulnAvailabilityImpact, 
        v4subConfidentialityImpact, v4subIntegrityImpact, v4subAvailabilityImpact, 
        v4exploitMaturity, v4confidentialityRequirement, v4integrityRequirement, 
        v4availabilityRequirement, v4modifiedAttackVector, v4modifiedAttackComplexity, 
        v4modifiedAttackRequirements, v4modifiedPrivilegesRequired, v4modifiedUserInteraction, 
        v4modifiedVulnConfidentialityImpact, v4modifiedVulnIntegrityImpact, v4modifiedVulnAvailabilityImpact, 
        v4modifiedSubConfidentialityImpact, v4modifiedSubIntegrityImpact, v4modifiedSubAvailabilityImpact, 
        v4safety, v4automatable, v4recovery, v4valueDensity, v4vulnerabilityResponseEffort, 
        v4providerUrgency, v4baseScore, v4baseSeverity, v4threatScore, v4threatSeverity, 
        v4environmentalScore, v4environmentalSeverity, v4source, v4type)
        VALUES (@cveId, @description, 
        @v2Severity, @v2ExploitabilityScore, 
        @v2ImpactScore, @v2AcInsufInfo, @v2ObtainAllPrivilege, 
        @v2ObtainUserPrivilege, @v2ObtainOtherPrivilege, @v2UserInteractionRequired, 
        @v2Score, @v2AccessVector, @v2AccessComplexity, 
        @v2Authentication, @v2ConfidentialityImpact, @v2IntegrityImpact, 
        @v2AvailabilityImpact, @v2Version, @v3ExploitabilityScore, 
        @v3ImpactScore, @v3AttackVector, @v3AttackComplexity, 
        @v3PrivilegesRequired, @v3UserInteraction, @v3Scope, 
        @v3ConfidentialityImpact, @v3IntegrityImpact, @v3AvailabilityImpact, 
        @v3BaseScore, @v3BaseSeverity, @v3Version, @v4version, @v4attackVector, 
        @v4attackComplexity, @v4attackRequirements, @v4privilegesRequired, 
        @v4userInteraction, @v4vulnConfidentialityImpact, @v4vulnIntegrityImpact, 
        @v4vulnAvailabilityImpact, @v4subConfidentialityImpact, @v4subIntegrityImpact, 
        @v4subAvailabilityImpact, @v4exploitMaturity, @v4confidentialityRequirement, 
        @v4integrityRequirement, @v4availabilityRequirement, @v4modifiedAttackVector, 
        @v4modifiedAttackComplexity, @v4modifiedAttackRequirements, @v4modifiedPrivilegesRequired, 
        @v4modifiedUserInteraction, @v4modifiedVulnConfidentialityImpact, @v4modifiedVulnIntegrityImpact, 
        @v4modifiedVulnAvailabilityImpact, @v4modifiedSubConfidentialityImpact, @v4modifiedSubIntegrityImpact, 
        @v4modifiedSubAvailabilityImpact, @v4safety, @v4automatable, @v4recovery, @v4valueDensity, 
        @v4vulnerabilityResponseEffort, @v4providerUrgency, @v4baseScore, @v4baseSeverity, 
        @v4threatScore, @v4threatSeverity, @v4environmentalScore, @v4environmentalSeverity,
        @v4source, @v4type);
        
        SET @vulnerabilityId = SCOPE_IDENTITY();
END;

SELECT @vulnerabilityId;

END

GO

CREATE PROCEDURE insert_software (
    @vulnerabilityId INT, @part CHAR(1), @vendor VARCHAR(255), @product VARCHAR(255),
    @version VARCHAR(255), @update_version VARCHAR(255), @edition VARCHAR(255), @lang VARCHAR(20),
    @sw_edition VARCHAR(255), @target_sw VARCHAR(255), @target_hw VARCHAR(255), @other VARCHAR(255), 
    @ecosystem VARCHAR(255), @versionEndExcluding VARCHAR(100), @versionEndIncluding VARCHAR(100), 
    @versionStartExcluding VARCHAR(100), @versionStartIncluding VARCHAR(100), @vulnerable BIT) AS
BEGIN
    DECLARE @cpeId INT;
    DECLARE @currentEcosystem VARCHAR(255);
    SET @cpeId=0;
    
    SELECT @cpeId=id, @currentEcosystem=ecosystem 
    FROM cpeEntry WHERE part=@part AND vendor=@vendor AND product=@product
        AND [version]=@version AND update_version=@update_version AND [edition]=@edition 
        AND lang=@lang AND sw_edition=@sw_edition AND target_sw=@target_sw 
        AND target_hw=@target_hw AND other=@other;

    IF @cpeId > 0
    BEGIN
        IF @currentEcosystem IS NULL AND @ecosystem IS NOT NULL
        BEGIN
            UPDATE cpeEntry SET ecosystem=@ecosystem WHERE id=@cpeId;
        END
    END
    ELSE
    BEGIN
        INSERT INTO cpeEntry (part, vendor, product, [version], update_version, 
            [edition], lang, sw_edition, target_sw, target_hw, other, ecosystem) 
        VALUES (@part, @vendor, @product, @version, @update_version, 
                @edition, @lang, @sw_edition, @target_sw, @target_hw, @other, @ecosystem);
        SET @cpeId = SCOPE_IDENTITY();
    END

    INSERT INTO software (cveid, cpeEntryId, versionEndExcluding, versionEndIncluding,
            versionStartExcluding, versionStartIncluding, vulnerable) 
    VALUES (@vulnerabilityId, @cpeId, @versionEndExcluding, @versionEndIncluding,
            @versionStartExcluding, @versionStartIncluding, @vulnerable);
END;

GO

CREATE PROCEDURE merge_knownexploited (@cveID varchar(20),
    @vendorProject VARCHAR(255),
    @product VARCHAR(255),
    @vulnerabilityName VARCHAR(500),
    @dateAdded CHAR(10),
    @shortDescription VARCHAR(2000),
    @requiredAction VARCHAR(1000),
    @dueDate CHAR(10),
    @notes VARCHAR(2000))
AS
BEGIN
IF EXISTS(SELECT * FROM knownExploited WHERE cveID=@cveID)
    UPDATE knownExploited
    SET vendorProject=@vendorProject, product=@product, vulnerabilityName=@vulnerabilityName, 
        dateAdded=@dateAdded, shortDescription=@shortDescription, requiredAction=@requiredAction, 
        dueDate=@dueDate, notes=@notes
    WHERE cveID=@cveID;
ELSE
    INSERT INTO knownExploited (vendorProject, product, vulnerabilityName,
        dateAdded, shortDescription, requiredAction, dueDate, notes, cveID) 
    VALUES (@vendorProject, @product, @vulnerabilityName,
        @dateAdded, @shortDescription, @requiredAction, @dueDate, @notes, @cveID);
END;

GO

INSERT INTO properties(id,value) VALUES ('version','5.5');

GO
/**
--dcuser with the default password should be given db_datareader
-- a new account used only for updates should be created and granted the following permissions.
CREATE LOGIN dcuser   
    WITH PASSWORD = 'DC-Pass1337!';  
GO
CREATE USER dcuser FOR LOGIN dcuser;  
GO
EXEC sp_addrolemember 'db_datareader', 'dcuser'
EXEC sp_addrolemember 'db_datawriter', 'dcuser'
GO 

GO
GRANT EXECUTE ON save_property TO dcuser; 
GRANT EXECUTE ON merge_ecosystem TO dcuser; 
GRANT EXECUTE ON update_vulnerability TO dcuser; 
GRANT EXECUTE ON insert_software TO dcuser; 
GO
**/
