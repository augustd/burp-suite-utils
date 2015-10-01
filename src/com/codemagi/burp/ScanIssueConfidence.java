package com.codemagi.burp;

import javax.swing.JComboBox;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public enum ScanIssueConfidence {

    CERTAIN("Certain", 30),
    FIRM("Firm", 20),
    TENTATIVE("Tentative", 10);

    private final String name;
    private final int value;

    private ScanIssueConfidence(String name, int value) {
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
        severityBox.addItem(CERTAIN.getName());
        severityBox.addItem(FIRM.getName());
        severityBox.addItem(TENTATIVE.getName());
	
	return severityBox;
    }

    public static ScanIssueConfidence fromName(String text) {
    if (text != null) {
      for (ScanIssueConfidence b : ScanIssueConfidence.values()) {
        if (text.equalsIgnoreCase(b.getName())) {
          return b;
        }
      }
    }
    return null;
  }
    
}
