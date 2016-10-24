package com.codemagi.burp.parser;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Cookie {
    
    String name;
    String value; 

    public Cookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
    
}
