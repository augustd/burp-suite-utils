package com.codemagi.burp.parser;

import java.util.Map;

/**
 * Sorts HTTP headers by <u>lower case</u> character code.
 * 
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class HeaderComparator implements java.util.Comparator<Map.Entry> {

    @Override
    public int compare(Map.Entry t1, Map.Entry t2) {
	
	String key1 = (String)t1.getKey();
	String key2 = (String)t2.getKey();
	
	return key1.toLowerCase().compareTo(key2.toLowerCase());
    }
    
}
