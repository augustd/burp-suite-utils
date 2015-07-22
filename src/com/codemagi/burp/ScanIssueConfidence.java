package com.codemagi.burp;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public enum ScanIssueConfidence {

    CERTAIN("Certain"),
    FIRM("Firm"),
    TENTATIVE("Tentative");

    private final String name;

    private ScanIssueConfidence(String name) {
	this.name = name;
    }

    public String getName() {
	return name;
    }
    
}
