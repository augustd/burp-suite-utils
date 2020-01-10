package com.codemagi.burp.ui;

import java.awt.Component;
import javax.swing.JTabbedPane;

/**
 * Creates a JTabbedPane customized to work with Burp. Includes: 
 * <li>Ability to rename tabs</li>
 * <li>Ability to close tabs</li>
 * <li>Burp-like UI</li>
 * 
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpTabbedPane extends JTabbedPane {
    
    /**
     * Add a new re-nameable, closable tab to the tabbed pane. 
     * 
     * @param name
     * @param component
     * @return 
     */
    @Override
    public Component add(String name, Component component) {
        //add the component that renders when the tab is selected
        Component output = super.add(name, component);
	//add the tab component: renders instead of the default tab name
        setTabComponentAt(indexOfComponent(component), new BurpTabComponent(name, this));
        return output;
    }
    
}
