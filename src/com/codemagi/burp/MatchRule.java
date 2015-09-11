package com.codemagi.burp;

import java.util.regex.Pattern;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class MatchRule {
    private String test;
    private Pattern pattern;
    private Integer matchGroup;
    private String type;
    private ScanIssueSeverity severity;


    public MatchRule(Pattern pattern, Integer matchGroup, String type) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
    }

    public MatchRule(Pattern pattern, Integer matchGroup, String type, ScanIssueSeverity severity) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
	this.severity = severity;
    }

    public MatchRule(String test, Pattern pattern, Integer matchGroup, String type) {
	this.test = test;
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
    }

    public MatchRule(String test, Pattern pattern, Integer matchGroup, String type, ScanIssueSeverity severity) {
	this.test = test;
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
	this.severity = severity;
    }

    public String getTest() {
	return test;
    }

    public Pattern getPattern() {
	return pattern;
    }

    public Integer getMatchGroup() {
	return matchGroup;
    }

    public String getType() {
	return type;
    }

    public ScanIssueSeverity getSeverity() {
	return severity;
    }
    
}
