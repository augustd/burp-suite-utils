package com.codemagi.burp.ui;

import burp.IBurpExtenderCallbacks;
import com.codemagi.burp.BaseExtender;
import com.codemagi.burp.BurpExtender;
import javax.swing.JPanel;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;


/*
 * Copyright 2020 adetlefsen.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpTabbedPaneTest {
			
	public BurpTabbedPaneTest() {
	}
	
    @BeforeClass
    public static void setUpClass() {
		//make sure there is an instance of BurpExtender
		BurpExtender extender = new BurpExtender();
	}
	
	/**
     * Test of adding tabs to BurpTabbedPane.
     */
    @Test
    public void testAdd() {
        System.out.println("testAdd");
		
		BurpTabbedPane pane = new BurpTabbedPane();
		pane.add("1", new JPanel());
		pane.add("2", new JPanel());
		
        assertEquals("1", pane.getTitleAt(0));
        assertEquals("2", pane.getTitleAt(1));
    }
	
	/**
     * Test of adding tabs to BurpTabbedPane, including a pinned last tab.
     */
    @Test
    public void testAddLast() {
        System.out.println("testAddLast");
		
		BurpTabbedPane pane = new BurpTabbedPane();
		pane.addLast("...", new JPanel());
		pane.add("1", new JPanel());
		pane.add("2", new JPanel());
		
        assertEquals("1", pane.getTitleAt(0));
        assertEquals("2", pane.getTitleAt(1));
        assertEquals("...", pane.getTitleAt(2));
    }
	
	/**
     * Test of adding tabs to BurpTabbedPane, including a pinned last tab added out of order.
     */
    @Test
    public void testAddLastOrdering() {
        System.out.println("testAddLastOrdering");
		
		BurpTabbedPane pane = new BurpTabbedPane();
		pane.add("1", new JPanel());
		pane.add("2", new JPanel());
		pane.addLast("...", new JPanel());
		pane.add("3", new JPanel());
		
        assertEquals("1", pane.getTitleAt(0));
        assertEquals("2", pane.getTitleAt(1));
        assertEquals("3", pane.getTitleAt(2));
        assertEquals("...", pane.getTitleAt(3));
    }
	
	/**
     * Test of adding tabs to BurpTabbedPane, including a pinned last tab added 
	 * multiple times.
     */
    @Test
    public void testAddLastMultiple() {
        System.out.println("testAddLastMultiple");
		
		BurpTabbedPane pane = new BurpTabbedPane();
		pane.addLast("...", new JPanel());
        assertEquals("...", pane.getTitleAt(0));
		
		//replace the existing last tab 
		pane.addLast("...1", new JPanel());
        assertEquals("...1", pane.getTitleAt(0));

		pane.add("1", new JPanel());
		pane.add("2", new JPanel());
		
        assertEquals("1", pane.getTitleAt(0));
        assertEquals("2", pane.getTitleAt(1));
        assertEquals("...1", pane.getTitleAt(2));
		
		//replace the existing last tab 
		pane.addLast("...2", new JPanel());
        assertEquals("...2", pane.getTitleAt(2));
    }
	
	/**
     * Test of adding tabs to BurpTabbedPane, including a pinned last tab added 
	 * multiple times.
     */
    @Test
    public void testRemove() {
        System.out.println("testRemove");
		
		BurpTabbedPane pane = new BurpTabbedPane();
		pane.add("1", new JPanel());
		pane.add("2", new JPanel());
		pane.addLast("...", new JPanel());
		
        assertEquals("1", pane.getTitleAt(0));
        assertEquals("2", pane.getTitleAt(1));
        assertEquals("...", pane.getTitleAt(2));
		
		//remove a regular tab 
		pane.remove(0);
        assertEquals("2", pane.getTitleAt(0));
        assertEquals("...", pane.getTitleAt(1));
		assertTrue(pane.hasLastTab());
		
		//remove the last tab 
		pane.remove(1);
        assertEquals("2", pane.getTitleAt(0));
		assertFalse(pane.hasLastTab());
    }

}
