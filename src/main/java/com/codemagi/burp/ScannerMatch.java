package com.codemagi.burp;

import java.util.regex.Pattern;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class ScannerMatch implements Comparable<ScannerMatch> {

    private String fullMatch;
    private String matchGroup;
    private String type;
    private ScanIssueSeverity severity;
    private ScanIssueConfidence confidence;
    private MatchRule rule;
    private Offsets offsets;

    public ScannerMatch(int start, int end, String match, String type) {
        offsets = new Offsets(start, end);
	this.matchGroup = match;
	this.type = type;
    }

    public ScannerMatch(Integer start, int end, String match, String type, ScanIssueSeverity severity) {
        offsets = new Offsets(start, end);
	this.matchGroup = match;
	this.type = type;
	this.severity = severity;
    }

    public ScannerMatch(Integer start, int end, String match, MatchRule rule) {
        offsets = new Offsets(start, end);
	this.matchGroup = match;
        this.rule = rule;
	this.type = rule.getType();
	this.severity = rule.getSeverity();
        this.confidence = rule.getConfidence();
    }

    public ScannerMatch(Integer start, int end, String fullMatch, String matchGroup, MatchRule rule) {
        offsets = new Offsets(start, end);
        this.fullMatch = fullMatch;
        this.matchGroup = matchGroup;
        this.rule = rule;
        this.type = rule.getType();
        this.severity = rule.getSeverity();
        this.confidence = rule.getConfidence();
    }

    public Integer getStart() {
	return offsets.getStart();
    }

    public Integer getEnd() {
        return offsets.getEnd();
    }

    public String getFullMatch() {
        return fullMatch;
    }

    public String getMatchGroup() {
        return matchGroup;
    }

    public MatchRule getRule() {
        return rule;
    }
	
    public Pattern getPattern() {
            return rule.getPattern();
    }
    
    public String getType() {
	return type;
    }    

    public ScanIssueSeverity getSeverity() {
	return severity;
    }

    public ScanIssueConfidence getConfidence() {
        return confidence;
    }
    
    @Override
    public int compareTo(ScannerMatch m) {
        return this.getStart().compareTo(m.getStart());
    }
    
    public Offsets getOffsets() {
        return offsets;
    }

}
