package com.monikamorrow.burp;

import burp.ITab;
import burp.IBurpExtenderCallbacks;
import java.awt.Component;
import javax.swing.JPanel;

/**
 * 
 * @author Monika Morrow Original URL: https://github.com/monikamorrow/Burp-Suite-Extension-Examples/tree/master/GUI%20Utils
 * @contributor August Detlefsen
 */
public class BurpSuiteTab extends javax.swing.JPanel implements ITab {
    IBurpExtenderCallbacks mCallbacks;
    String tabName; 
    JPanel userDefinedPanel;
    
    /**
     * Creates new form BurpSuiteTab
     * @param tabName     The name displayed on the tab
     * @param callbacks   For UI Look and Feel
     */
    public BurpSuiteTab(String tabName, IBurpExtenderCallbacks callbacks) {
	this.tabName = tabName;
        mCallbacks = callbacks;
        
        mCallbacks.customizeUiComponent(this);
        mCallbacks.addSuiteTab(this);
    }
    
    public void addComponent(JPanel customPanel) {
        this.add(customPanel);
        this.revalidate();
        this.doLayout();
    }
    
    @Override
    public String getTabCaption() {
	return tabName;
    }

    @Override
    public Component getUiComponent() {
	return this;
    }
}