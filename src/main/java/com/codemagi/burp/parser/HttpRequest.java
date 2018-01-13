package com.codemagi.burp.parser;

import burp.ICookie;
import burp.IParameter;
import burp.impl.Cookie;
import burp.impl.Parameter;
import com.codemagi.burp.Utils;
import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.regex.*;

/**
 * Generic http request parser. Messages are of the general form:
 * <pre>
 * status_line
 * header: value
 * header: value
 * header: value
 * ...
 * </pre> where status_line is something like
 * <pre>GET /foobar HTTP/1.0</pre>
 *
 * <p>
 * This class will parse all the header/value pairs and store them in a
 * ({@link java.util.LinkedHashMap}), and parse the first line as 'command'. The
 * <tt>LinkedHashMap</tt> will assure that an iterator will visit the fields in
 * the order the were originally sent/parsed.
 *
 * Note that parameters sent in the body of POST requests are not parsed.
 * Instead they are stored as-is in the 'body' member.
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class HttpRequest {

    //protected URL url;
    protected String method;
    protected String path;
    protected String version;
    protected String body;
    protected LinkedHashMap<String, String> headers = new LinkedHashMap<>();
    protected LinkedHashMap<String, String> sortedHeaders = null;
    protected LinkedHashMap<String, String> sortedParams = null;
    protected List<Parameter> parameters = new ArrayList<>();

    public final static char CR  = (char) 0x0D;
    public final static char LF  = (char) 0x0A; 
    public final static String CRLF  = "" + CR + LF;
    
    /**
     * Private no-argument constructor is only used internally by static factory
     * methods.
     */
    private HttpRequest() {
    }

    /**
     * Shorthand constructor for creating an HttpMessage from a URL.
     *
     * This method will create an HTTP/1.1 GET request with the URI passed in
     * the 'url' parameter. A 'Host' header will be set with the host portion of
     * the 'url' parameter.
     *
     * @param url The URL to construct a request for
     */
    public HttpRequest(URL url) {
        this(url, "GET");
    }

    /**
     * Constructor for creating an HttpMessage from a URL and an HTTP method.
     *
     * This method will create an HTTP/1.1 request with the URI passed in the
     * 'url' parameter. A 'Host' header will be set with the host portion of the
     * 'url' parameter
     *
     * @param url The URL to construct a request for
     * @param method The HTTP method to use for the new request
     */
    public HttpRequest(URL url, String method) {
        this.method = method;

        //set the uri of the request
        this.path = url.getPath();

        if (!Utils.isEmpty(url.getQuery())) {
            parseParameters(url.getQuery());
        }

        this.version = "HTTP/1.1";
        this.setHeader("Host", url.getHost());
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getVersion() {
        return version;
    }

    /**
     *
     * @return The body of the POST request, if there is one
     */
    public String getBody() {
        return Utils.noNulls(body);
    }

    /**
     * Converts a GET request to a POST request: changes request method and
     * moves any URL parameters to the HTTP message body.
     */
    public void convertToPost() {
        this.method = "POST";

        //add parameters, if available 
        StringBuilder bodyBuilder = new StringBuilder();
        boolean first = true;

        for (Parameter param : parameters) {

            if (!first) {
                bodyBuilder.append("&");
            }

            bodyBuilder.append(param.getName());
            bodyBuilder.append("=");
            bodyBuilder.append(param.getValue());

            first = false;
        }
        this.body = bodyBuilder.toString();
        this.parameters = new ArrayList<>();
        this.sortedParams = null;
    }
    
    /**
     * Converts a GET request to a Multipart/form-data request: changes request 
     * method to POST, adds Content-Type/boundary header and moves any URL 
     * parameters to the HTTP message body, formatted as a multipart request.
     */
    public void convertToMultipart() {
        this.method = "POST";
        
        String boundary = UUID.randomUUID().toString().replaceAll("-", "");
        setHeader("Content-Type", "multipart/form-data; boundary=----" + boundary);
        
        //add parameters, if available 
        StringBuilder bodyBuilder = new StringBuilder();

        for (Parameter param : parameters) {
            bodyBuilder.append("------").append(boundary).append(CRLF);
            bodyBuilder.append("Content-Disposition: form-data; name=\"").append(param.getName()).append("\"");
            if (param.getType() == IParameter.PARAM_MULTIPART_ATTR) {
                bodyBuilder.append("; filename=\"").append(param.getFilename()).append("\"").append(CRLF);
                bodyBuilder.append("Content-Type: ").append(param.getContentType());
            }
            bodyBuilder.append(CRLF).append(CRLF);
            
            bodyBuilder.append(param.getValue());
            bodyBuilder.append(CRLF);
        }
        bodyBuilder.append("------").append(boundary).append("--").append(CRLF);

        this.body = bodyBuilder.toString();
        this.parameters = new ArrayList<>();
        this.sortedParams = null;
    }

    /**
     * Returns the map of HTTP headers contained in this message, sorted by
     * <u>lower case</u> character order.
     *
     * If the map of sorted headers has already been created that will be
     * returned. Otherwise, a new LinkedHashMap will be constructed and cached
     * for future use.
     *
     * @return A LinkedHashMap containing the sorted HTTP headers, using the
     * header names as the hash key
     * @see java.util.LinkedHashMap
     */
    public LinkedHashMap getHeadersSorted() {
        if (sortedHeaders != null) {
            return sortedHeaders;
        }

        sortedHeaders = new LinkedHashMap<String, String>(headers.size());

        List<Map.Entry> headerEntries = new ArrayList(headers.entrySet());

        Collections.sort(headerEntries, new HeaderComparator());

        for (Map.Entry entry : headerEntries) {
            String name = (String) entry.getKey();
            String value = (String) entry.getValue();

            sortedHeaders.put(name, value);
        }

        return sortedHeaders;
    }

    /**
     * Sets a header field value based on its name.
     *
     * @param name The header name to set
     * @param value The header value to set
     * @return the previous value or null if the field was previously unset.
     */
    public final String setHeader(String name, String value) {
        sortedHeaders = null;
        return headers.put(name, value);
    }

    public String getHeader(String name) {
        return headers.get(name);
    }

    /**
     * Sets the Content-Length header to the current size of the request body
     * 
     * @return The length of the body content
     */
    public int setContentLength() {
        int contentLength = Utils.noNulls(body).length();
        setHeader("Content-Length", contentLength + "");
        return contentLength;
    }

    /**
     * Gets the value of the Cookie header
     *
     * @return A list containing Cookie objects parsed from the internal string
     * representation
     */
    public List<ICookie> getCookies() {
        String cookies = getHeader("Cookie");
        List<ICookie> output = new ArrayList<>();

        if (Utils.isEmpty(cookies)) {
            return output;
        }

        for (String cookieStr : cookies.split("[; ]+")) {
            String[] pair = cookieStr.split("=", 2);
            output.add(new Cookie(pair[0], pair[1]));
        }
        return output;
    }

    public void setCookies(List<ICookie> cookies) {
        StringBuilder buffer = new StringBuilder(cookies.size() * 40);
        for (ICookie cookie : cookies) {
            buffer.append(cookie.getName()).append("=").append(cookie.getValue()).append("; ");
        }
        setHeader("Cookie", buffer.toString());
    }

    public void addCookie(ICookie newCookie) {
        if (newCookie == null || Utils.isEmpty(newCookie.getName())) {
            return;
        }

        //check if this cookie exists already
        boolean found = false;
        List<ICookie> cookies = getCookies();
        for (ICookie oldCookie : cookies) {
            if (newCookie.getName().equals(oldCookie.getName())) {
                //update old cookie with new value
                Collections.replaceAll(cookies, oldCookie, newCookie);
                found = true;
                break;
            }
        }

        if (!found) {
            //add new cookie
            cookies.add(newCookie);
        }

        //set the cookie array back into this object's String representation
        setCookies(cookies);
    }

    public void addCookie(String name, String value) {
        addCookie(new Cookie(name, value));
    }

    /**
     * Sets a parameter value based on its name.
     *
     * @param name The parameter name to set
     * @param value The parameter value to set
     */
    public void setParameter(String name, String value) {
        sortedParams = null;
        parameters.add(new Parameter(name, value));
    }

    /**
     * Sets a parameter using a Parameter object.
     *
     * @param param The parameter to add
     */
    public void setParameter(Parameter param) {
        sortedParams = null;
        parameters.add(param);
    }

    /**
     * Sets the body of the HTTP request and updates the Content-Length header.
     * NOTE: This value will override any parameters previously set
     *
     * @param body The new request body
     */
    public void setBody(String body) {
        this.body = body;
        this.setContentLength();
    }

    /**
     * Returns the map of http parameters contained in this message, sorted by
     * <u>lower case</u> character order.
     *
     * If the map of sorted parameters has already been created that will be
     * returned. Otherwise, a new LinkedHashMap will be constructed and cached
     * for future use.
     *
     * @return A LinkedHashMap containing the sorted HTTP parameters, using the
     * parameter name as the key
     * @see java.util.LinkedHashMap
     */
    public LinkedHashMap getParametersSorted() {
        if (sortedParams != null) {
            return sortedParams;
        }

        sortedParams = new LinkedHashMap<>(parameters.size());

        List<Parameter> entries = new ArrayList(parameters);

        Collections.sort(entries, new ParameterComparator());

        for (Parameter entry : entries) {
            String name = (String) entry.getName();
            String value = (String) entry.getValue();

            sortedParams.put(name, value);
        }

        return sortedParams;
    }

    /**
     * Parses a new HttpMessage using {@link #parse(InputStream)} with out as
     * null.
     *
     * @param in The InputStream to parse
     * @return An HttpMessage object parsed from the InputStream
     * @throws java.io.IOException Any IO Exceptions will be thrown
     */
    public static HttpRequest parseMessage(InputStream in) throws IOException {
        HttpRequest m = new HttpRequest();
        m.parse(in);
        return m;
    }

    /**
     * Parses a new HttpMessage using {@link #parse(InputStream)} with out as
     * null.
     *
     * @param in The array of bytes to parse
     * @return An HttpMessage object parsed from the array
     * @throws java.io.IOException Any IO Exceptions will be thrown
     */
    public static HttpRequest parseMessage(byte[] in) throws IOException {
        HttpRequest m = new HttpRequest();
        m.parse(new ByteArrayInputStream(in));
        return m;
    }

    public static HttpRequest parseMessage(String in) throws IOException {
        if (in != null) {
            return parseMessage(in.getBytes());
        }
        return new HttpRequest();
    }

    /**
     * Parses an http message from an input stream. The first line of input is
     * save in the protected <tt>command</tt> variable. The subsequent lines are
     * put into a linked hash as field/value pairs. Input is parsed until a
     * blank line is reached, after which any data should appear.
     *
     * @param in An InputStream containing a valid HTTP message
     */
    private void parse(InputStream in) throws IOException {
        Pattern p = Pattern.compile(":");
        BufferedReader bin = new BufferedReader(new InputStreamReader(in), 1);
        String currLine = bin.readLine();
        //command = currLine;

        //parse the command to get the request method
        parseCommand(currLine);

        //parse headers
        currLine = bin.readLine();
        while (currLine != null) {

            if (Utils.isEmpty(currLine)) {
                break;  //we have reached the end of the headers
            }

            //split the headers into name-value pairs
            String[] split = currLine.split(": ");
            
            if (split.length < 2) {
                split = new String[] {
                    split[0], ""
                };
            }

            String headerName = Utils.trim(split[0]);
            String headerValue = Utils.trim(split[1]);

            headers.put(headerName, headerValue);

            currLine = bin.readLine();
        }

        //parse the POST body, if there is one
        if (currLine != null) {
            currLine = bin.readLine();
            if (currLine != null) {
                body = currLine;
            }
        }

    }

    private void parseCommand(String command) {
        if (Utils.isEmpty(command)) {
            return;
        }

        String[] parts = command.split(" ");
        method = (parts.length > 0) ? parts[0] : "";
        String uri = (parts.length > 1) ? parts[1] : "";
        version = (parts.length > 2) ? parts[2] : "";

        if (!Utils.isEmpty(uri)) {

            String[] split = uri.split("\\?");

            path = (split.length > 0) ? split[0] : "";

            //see if there are any query params
            if (split.length > 1) {
                parseParameters(split[1]);
            }

        }

    }

    /**
     * Parses a String of HTTP parameters into the internal parameters data
     * structure. No input checking or decoding is performed!
     *
     * @param input A String of HTTP parameters in the form of:
     * name1=value1&name2=value2&...
     */
    private void parseParameters(String input) {
        for (String param : input.split("&")) {
            String[] pair = param.split("=");

            String name = (pair.length > 0) ? pair[0] : null;
            String value = (pair.length > 1) ? pair[1] : null;

            if (name != null) {
                setParameter(name, value);
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder output = new StringBuilder(1024);

        //Add the command
        output.append(method).append(" ");
        output.append(path);

        //add parameters, if available 
        if (!parameters.isEmpty()) {
            output.append("?");

            boolean first = true;

            for (Parameter param : parameters) {

                if (!first) {
                    output.append("&");
                }

                output.append(param.getName());
                output.append("=");
                output.append(Utils.noNulls(param.getValue()));

                first = false;
            }
        }

        output.append(" ");
        output.append(version).append("\r\n");

        //add the headers
        for (Map.Entry header : headers.entrySet()) {
            output.append(header.getKey());
            output.append(": ");
            output.append(Utils.noNulls(header.getValue()));
            output.append("\r\n");
        }

        output.append("\r\n");

        //add the request body
        output.append(getBody());

        return output.toString();
    }

    public byte[] getBytes() {
        return toString().getBytes();
    }

}
