package com.codemagi.burp;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public enum ScanIssueSeverity {

    HIGH("High", 50),
    MEDIUM("Medium", 40),
    LOW("Low", 30),
    INFO("Information", 20),
    FALSE_POSITIVE("False positive", 10);

    private final String name;
    private final int value;

    private ScanIssueSeverity(String name, int value) {
	this.name = name;
	this.value = value;
    }

    public String getName() {
	return name;
    }

    public int getValue() {
	return value;
    }

}
