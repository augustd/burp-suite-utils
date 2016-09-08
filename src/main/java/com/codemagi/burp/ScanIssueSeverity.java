package com.codemagi.burp;

import javax.swing.JComboBox;

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
    
    public static JComboBox getComboBox() {
	JComboBox severityBox = new JComboBox();
        severityBox.addItem(HIGH.getName());
        severityBox.addItem(MEDIUM.getName());
        severityBox.addItem(LOW.getName());
        severityBox.addItem(INFO.getName());
        severityBox.addItem(FALSE_POSITIVE.getName());
	
	return severityBox;
    }

    public static ScanIssueSeverity fromName(String text) {
    if (text != null) {
      for (ScanIssueSeverity b : ScanIssueSeverity.values()) {
        if (text.equalsIgnoreCase(b.getName())) {
          return b;
        }
      }
    }
    return null;
  }
    
}
