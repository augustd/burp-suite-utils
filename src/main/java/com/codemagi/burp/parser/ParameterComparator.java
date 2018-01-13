package com.codemagi.burp.parser;

import burp.impl.Parameter;

/**
 * Sorts HTTP parameters by character code. Sorting is <u>case sensitive</u>, i.e. parameter 'UserName' comes BEFORE 'maxItems'.
 * 
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class ParameterComparator implements java.util.Comparator<Parameter> {

    @Override
    public int compare(Parameter t1, Parameter t2) {
	
	String key1 = (String)t1.getName();
	String key2 = (String)t2.getName();
	
	return key1.compareTo(key2);
    }
    
}
