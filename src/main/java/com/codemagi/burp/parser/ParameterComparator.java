package com.codemagi.burp.parser;

import java.util.Map;

/**
 * Sorts HTTP parameters by character code. Sorting is <u>case sensitive</u>, i.e. parameter 'UserName' comes BEFORE 'maxItems'.
 * 
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class ParameterComparator implements java.util.Comparator<Map.Entry> {

    @Override
    public int compare(Map.Entry t1, Map.Entry t2) {
	
	String key1 = (String)t1.getKey();
	String key2 = (String)t2.getKey();
	
	return key1.compareTo(key2);
    }
    
}
