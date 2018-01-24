package burp.impl;

import burp.ICookie;
import com.codemagi.burp.BaseExtender;
import com.codemagi.burp.Utils;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
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
    Long maxAge;
    Boolean secure = false;
    Boolean httpOnly = false;

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

    /**
     * Parses a cookie from a String containing the raw HTTP response header 
     * _value_ (Minus "Set-Cookie:"). 
     *
     * @param rawCookie A String containing the raw cookie 
     * @return A Cookie object parsed from the raw cookie string 
     * @throws ParseException if the cookie does not have at least a name
     */
    public static Cookie parseCookie(String rawCookie) throws ParseException {
        String[] rawCookieParams = rawCookie.split(";");

        //get the cookie name, check for valid cookie
        String[] rawCookieNameAndValue = rawCookieParams[0].split("=");
        String cookieName = rawCookieNameAndValue[0].trim();
        if (Utils.isEmpty(cookieName)) {
            throw new ParseException("Invalid cookie: missing name", 0);
        }

        //get the cookie value
        String cookieValue = rawCookieNameAndValue[1].trim();
        
        //construct output
        Cookie output = new Cookie(cookieName, cookieValue);
        
        //parse other cookie params
        for (int i = 1; i < rawCookieParams.length; i++) {
            String[] rawCookieParam = rawCookieParams[i].trim().split("=");

            String paramName = rawCookieParam[0].trim();

            if ("secure".equalsIgnoreCase(paramName)) {
                output.setSecure(true);
                
            } else if ("HttpOnly".equalsIgnoreCase(paramName)) {
                output.setHttpOnly(true);
                
            } else {
                if (rawCookieParam.length != 2) {
                    //attribute not a flag or missing value
                    continue;
                }
                String paramValue = rawCookieParam[1].trim();

                if ("expires".equalsIgnoreCase(paramName)) {
                    try {
                        SimpleDateFormat format = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss zzz");
                        Date expiryDate = format.parse(paramValue);
                        output.setExpiration(expiryDate);
                    } catch (Exception e) {
                        //couldn't parse date, ignore
                        BaseExtender.getCallbacks().printError("WARNING: unable to parse cookie expiration: " + paramValue);
                    }
                } else if ("max-age".equalsIgnoreCase(paramName)) {
                    long maxAge = Long.parseLong(paramValue);
                    output.setMaxAge(maxAge);

                } else if ("domain".equalsIgnoreCase(paramName)) {
                    output.setDomain(paramValue);
                    
                } else if ("path".equalsIgnoreCase(paramName)) {
                    output.setPath(paramValue);
                    
                }
            }
        }

        return output;
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

    public Long getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(Long maxAge) {
        this.maxAge = maxAge;
    }

    public Boolean getSecure() {
        return secure;
    }

    public void setSecure(Boolean secure) {
        this.secure = secure;
    }

    public Boolean getHttpOnly() {
        return httpOnly;
    }

    public void setHttpOnly(Boolean httpOnly) {
        this.httpOnly = httpOnly;
    }
}
