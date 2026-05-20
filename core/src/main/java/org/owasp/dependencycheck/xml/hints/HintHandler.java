/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.owasp.dependencycheck.xml.suppression.PropertyType;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.ArrayList;
import java.util.List;

/**
 * A handler to load hint rules.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class HintHandler extends DefaultHandler {

    /**
     * Internal type to track the parent node state.
     */
    enum ParentType {
        /**
         * Marks the add node.
         */
        ADD,
        /**
         * Marks the given node.
         */
        GIVEN,
        /**
         * Marks the remove node.
         */
        REMOVE
    }

    //<editor-fold defaultstate="collapsed" desc="Element and attribute names">
    /**
     * Element name.
     */
    private static final String HINT = "hint";
    /**
     * Element name.
     */
    private static final String GIVEN = "given";
    /**
     * Element name.
     */
    private static final String ADD = "add";
    /**
     * Element name.
     */
    private static final String REMOVE = "remove";

    /**
     * Element name.
     */
    private static final String EVIDENCE = "evidence";
    /**
     * Element name.
     */
    private static final String FILE_NAME = "fileName";
    /**
     * Element name.
     */
    private static final String VENDOR_DUPLICATING_RULE = "vendorDuplicatingHint";
    /**
     * Attribute name.
     */
    private static final String DUPLICATE = "duplicate";
    /**
     * Attribute value.
     */
    private static final String VENDOR = "vendor";
    /**
     * Attribute value.
     */
    private static final String PRODUCT = "product";
    /**
     * Attribute value.
     */
    private static final String VERSION = "version";
    /**
     * Attribute name.
     */
    private static final String CONFIDENCE = "confidence";
    /**
     * Attribute name.
     */
    private static final String VALUE = "value";
    /**
     * Attribute name.
     */
    private static final String NAME = "name";
    /**
     * Attribute name.
     */
    private static final String SOURCE = "source";
    /**
     * Attribute name.
     */
    private static final String TYPE = "type";
    /**
     * Attribute name.
     */
    private static final String CASE_SENSITIVE = "caseSensitive";
    /**
     * Attribute name.
     */
    private static final String REGEX = "regex";
    /**
     * Attribute name.
     */
    private static final String CONTAINS = "contains";
    //</editor-fold>

    /**
     * The list of hint rules.
     */
    private final List<HintRule> hintRules = new ArrayList<>();

    /**
     * The list of vendor duplicating hint rules.
     */
    private final List<VendorDuplicatingHintRule> vendorDuplicatingHintRules = new ArrayList<>();
    /**
     * The current rule being read.
     */
    private HintRule rule;

    /**
     * The current state of the parent node (to differentiate between 'add' and
     * 'given').
     */
    private ParentType nodeType = ParentType.GIVEN;

    /**
     * Returns the list of hint rules.
     *
     * @return the value of hintRules
     */
    public List<HintRule> getHintRules() {
        return hintRules;
    }

    /**
     * Returns the list of vendor duplicating hint rules.
     *
     * @return the list of vendor duplicating hint rules
     */
    public List<VendorDuplicatingHintRule> getVendorDuplicatingHintRules() {
        return vendorDuplicatingHintRules;
    }

    /**
     * Handles the start element event.
     *
     * @param uri the URI of the element being processed
     * @param localName the local name of the element being processed
     * @param qName the qName of the element being processed
     * @param attr the attributes of the element being processed
     * @throws SAXException thrown if there is an exception processing
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attr) throws SAXException {
        if (null != qName) {
            switch (qName) {
                case HINT:
                    rule = new HintRule();
                    break;
                case ADD:
                    nodeType = ParentType.ADD;
                    break;
                case GIVEN:
                    nodeType = ParentType.GIVEN;
                    break;
                case REMOVE:
                    nodeType = ParentType.REMOVE;
                    break;
                case EVIDENCE:
                    final String hintType = attr.getValue(TYPE);
                    if (null != hintType && null != nodeType) {
                        final String source = attr.getValue(SOURCE);
                        final String name = attr.getValue(NAME);
                        final String value = attr.getValue(VALUE);
                        final Confidence confidence;
                        final String confidenceAttribute = attr.getValue(CONFIDENCE);
                        if (confidenceAttribute == null) {
                            confidence = null;
                        } else {
                            confidence = Confidence.valueOf(confidenceAttribute);
                        }
                        final boolean regex;
                        final String regexAttribute = attr.getValue(REGEX);
                        if (regexAttribute == null) {
                            regex = false;
                        } else {
                            regex = XmlUtils.parseBoolean(regexAttribute);
                        }
                        switch (hintType) {
                            case VENDOR:
                                switch (nodeType) {
                                    case ADD:
                                        rule.addAddVendor(source, name, value, confidence);
                                        break;
                                    case REMOVE:
                                        rule.addRemoveVendor(source, name, value, regex, confidence);
                                        break;
                                    case GIVEN:
                                        rule.addGivenVendor(source, name, value, regex, confidence);
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case PRODUCT:
                                switch (nodeType) {
                                    case ADD:
                                        rule.addAddProduct(source, name, value, confidence);
                                        break;
                                    case REMOVE:
                                        rule.addRemoveProduct(source, name, value, regex, confidence);
                                        break;
                                    case GIVEN:
                                        rule.addGivenProduct(source, name, value, regex, confidence);
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case VERSION:
                                switch (nodeType) {
                                    case ADD:
                                        rule.addAddVersion(source, name, value, confidence);
                                        break;
                                    case REMOVE:
                                        rule.addRemoveVersion(source, name, value, regex, confidence);
                                        break;
                                    case GIVEN:
                                        rule.addGivenVersion(source, name, value, regex, confidence);
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case FILE_NAME:
                    boolean isRegex = false;
                    boolean isCaseSensitive = false;
                    if (attr.getLength() > 0) {
                        final String regex = attr.getValue(REGEX);
                        if (regex != null) {
                            isRegex = Boolean.parseBoolean(regex);
                        }
                        final String caseSensitive = attr.getValue(CASE_SENSITIVE);
                        if (caseSensitive != null) {
                            isCaseSensitive = Boolean.parseBoolean(caseSensitive);
                        }
                    }
                    rule.addFilename(new PropertyType(attr.getValue(CONTAINS), isRegex, isCaseSensitive));
                    break;
                case VENDOR_DUPLICATING_RULE:
                    vendorDuplicatingHintRules.add(new VendorDuplicatingHintRule(attr.getValue(VALUE), attr.getValue(DUPLICATE)));
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Handles the end element event.
     *
     * @param uri the element's URI
     * @param localName the local name
     * @param qName the qualified name
     * @throws SAXException thrown if there is an exception processing the
     * element
     */
    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        if (HINT.equals(qName) && rule != null) {
            hintRules.add(rule);
            rule = null;
        }
    }
}
