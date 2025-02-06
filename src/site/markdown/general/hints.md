Resolving False Negatives
====================
Due to how dependency-check identifies libraries, false negatives may occur (a CPE was NOT identified for a library). Identifying these false negatives can be accomplished using the HTML report. In the report, click on the "Display: Showing Vulnerable Dependencies (click to show all)" link. You can then browse the dependencies and review the CPEs that are there for accuracy. You can also review the dependencies where no CPE match was made. Using the CPE dictionary search manually to verify that there is a CPE to match is a good verification that a false negative has been found. If you identify a dependency that is missing a CPE you can add evidence to help identify the correct CPE.

A possible reason for false negatives is re-naming of either the vendor or library name over time. Another case is when an artifact has missing info (manifest with no vendor).

Dependency Check has a built in [hints](https://github.com/dependency-check/DependencyCheck/blob/main/core/src/main/resources/dependencycheck-base-hint.xml) file that is used in every check to help correct well known false negatives.

A sample hints file that add a product name and possible vendors for Spring framework dependencies would look like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<hints xmlns="https://jeremylong.github.io/DependencyCheck/dependency-hint.1.1.xsd">
    <hint>
        <given>
            <evidence type="product" source="Manifest" name="Implementation-Title" value="Spring Framework" confidence="HIGH"/>
            <evidence type="product" source="Manifest" name="Implementation-Title" value="org.springframework.core" confidence="HIGH"/>
            <evidence type="product" source="Manifest" name="Implementation-Title" value="spring-core" confidence="HIGH"/>
        </given>
        <add>
            <evidence type="product" source="hint analyzer" name="product" value="springsource_spring_framework" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="SpringSource" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="vmware" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="pivotal" confidence="HIGH"/>
        </add>
    </hint>
</hints>

```
The above XML file will add the 4 evidence entries to any dependency that matches any one of the 3 givens.

The following shows some other ways to add evidence

```xml
<?xml version="1.0" encoding="UTF-8"?>
<hints xmlns="https://jeremylong.github.io/DependencyCheck/dependency-hint.1.1.xsd">
   <hint>
        <given>
            <evidence type="product" source="jar" name="package name" value="springframework" confidence="LOW"/>
            <fileName contains="spring"/>
        </given>
        <add>
            <evidence type="product" source="hint analyzer" name="product" value="springsource_spring_framework" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="SpringSource" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="vmware" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="pivotal" confidence="HIGH"/>
        </add>
   </hint>
   <hint>
        <given>
            <fileName contains="my-thelib-.*\.jar" regex="true" caseSensitive="true"/>
        </given>
        <add>
            <evidence type="product" source="hint analyzer" name="product" value="thelib" confidence="HIGH"/>
            <evidence type="vendor" source="hint analyzer" name="vendor" value="thevendor" confidence="HIGH"/>
        </add>
  </hint>
</hints>
```


The full schema for hints files can be found here: [dependency-hint.xsd](https://github.com/dependency-check/DependencyCheck/blob/main/core/src/main/resources/schema/dependency-hint.1.1.xsd "Hint Schema")

Please see the appropriate configuration option in each interfaces configuration guide:

-  [Command Line Tool](../dependency-check-cli/arguments.html)
-  [Maven Plugin](../dependency-check-maven/configuration.html)
-  [Gradle Plugin](../dependency-check-gradle/configuration.html)
-  [Ant Task](../dependency-check-ant/configuration.html)
-  [Jenkins Plugin](../dependency-check-jenkins/index.html)
