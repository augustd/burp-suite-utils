package com.codemagi.burp.ui;

import java.awt.Component;
import javax.swing.JTabbedPane;

/**
 * Creates a JTabbedPane customized to work with Burp. Includes:
 * <ul>
 * <li>Ability to rename tabs</li>
 * <li>Ability to close tabs</li>
 * <li>Optional pinned 'last tab'</li>
 * <li>Burp-like UI</li>
 * </ul>
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpTabbedPane extends JTabbedPane {

	private boolean hasLast = false;

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
		int index = hasLast ? getTabCount()-1 : getTabCount() ;
		insertTab(name, null, component, null, index);
		//add the tab component: renders instead of the default tab name
		setTabComponentAt(indexOfComponent(component), new BurpTabComponent(name, this));
		return component;
	}

	/**
	 * Adds a new tab at the last position of the tabbed pane. New tab is
	 * non-closable, non-renameable and always remains in the last position.
	 *
	 * NOTE: There can be only one <i>last tab</i>. Calling this method again
	 * will replace the one previously added.
	 *
	 * @param name
	 * @param component
	 * @return
	 */
	public void addLast(String name, Component component) {
		if (hasLast) {
			//remove existing last tab
			remove(Math.max(0, getTabCount()-1));
		}
		//add the component at the last position
		insertTab(name, null, component, null, getTabCount());
		hasLast = true;
	}

	/**
	 * Overridden to handle the case of removing the last tab.
	 */
	@Override
	public void removeAll() {
		hasLast = false;
		super.removeAll();
	}

	/**
	 * Overridden to handle the case of removing the last tab.
	 */
	@Override
	public void remove(int index) {
		if (hasLast && isLastTab(index)) hasLast = false;
		super.remove(index);
	}

	/**
	 * Overridden to handle the case of removing the last tab.
	 */
	@Override
	public void remove(Component component) {
		if (hasLast && isLastTab(indexOfComponent(component))) hasLast = false;
		super.remove(component);
	}

	/**
	 * Overridden to handle the case of removing the last tab.
	 */
	@Override
	public void removeTabAt(int index) {
		if (hasLast && isLastTab(index)) hasLast = false;
		super.removeTabAt(index); //To change body of generated methods, choose Tools | Templates.
	}

	public boolean isLastTab(int index) {
		return index == Math.max(0, getTabCount()-1);
	}

	public boolean hasLastTab() {
		return hasLast;
	}

}
