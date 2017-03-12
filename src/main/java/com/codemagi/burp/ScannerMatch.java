package com.codemagi.burp;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class ScannerMatch implements Comparable<ScannerMatch> {

    private Integer start;
    private int end;
	private String fullMatch;
    private String matchGroup;
    private String type;
    private ScanIssueSeverity severity;
    private ScanIssueConfidence confidence;

    public ScannerMatch(int start, int end, String match, String type) {
	this.start = start;
	this.end = end;
	this.matchGroup = match;
	this.type = type;
    }

    public ScannerMatch(Integer start, int end, String match, String type, ScanIssueSeverity severity) {
	this.start = start;
	this.end = end;
	this.matchGroup = match;
	this.type = type;
	this.severity = severity;
    }

    public ScannerMatch(Integer start, int end, String match, MatchRule rule) {
	this.start = start;
	this.end = end;
	this.matchGroup = match;
	this.type = rule.getType();
	this.severity = rule.getSeverity();
        this.confidence = rule.getConfidence();
    }

    public ScannerMatch(Integer start, int end, String fullMatch, String matchGroup, MatchRule rule) {
		this.start = start;
		this.end = end;
		this.fullMatch = fullMatch;
		this.matchGroup = matchGroup;
		this.type = rule.getType();
		this.severity = rule.getSeverity();
        this.confidence = rule.getConfidence();
    }

    public int getStart() {
	return start;
    }

    public int getEnd() {
	return end;
    }

	public String getFullMatch() {
		return fullMatch;
	}

	public String getMatchGroup() {
		return matchGroup;
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
        return start.compareTo(m.getStart());
    }
    
}
