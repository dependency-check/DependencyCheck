package org.owasp.dependencycheck.xml.suppression;

import java.util.Objects;

/**
 * Represents a single suppression entry inside a suppression rule.
 * This can be a CVE, vulnerability name, CWE, CPE, or CVSS-based suppression.
 */
public final class SuppressionEntry {

    public enum Type {
        CVE,
        VULNERABILITY_NAME,
        CWE,
        CPE,
        CVSS
    }

    private final Type type;
    private final PropertyType property; // null for CVSS-based entries

    public SuppressionEntry(Type type, PropertyType property) {
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.property = property;
    }

    public Type getType() {
        return type;
    }

    public PropertyType getProperty() {
        return property;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SuppressionEntry)) return false;
        SuppressionEntry that = (SuppressionEntry) o;
        return type == that.type &&
                Objects.equals(property, that.property);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, property);
    }

    @Override
    public String toString() {
        if (property != null) {
            return type + ":" + property.getValue();
        }
        return type.toString();
    }
}
