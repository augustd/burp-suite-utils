package com.codemagi.burp;

import javax.swing.JComboBox;

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
