package burp.impl;

import burp.ICookie;
import java.util.Date;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Cookie implements ICookie {
    
    String name;
    String value; 
    String domain;
    String path;
    Date expiration;

    public Cookie(String name, String value) {
        this.name = name;
        this.value = value;
    }
    
    public Cookie(ICookie cookie) {
        this.name = cookie.getName();
        this.value = cookie.getValue();
        this.domain = cookie.getDomain();
        this.path = cookie.getPath();
        this.expiration = cookie.getExpiration();
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Override
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public Date getExpiration() {
        return expiration;
    }
    
    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

}
