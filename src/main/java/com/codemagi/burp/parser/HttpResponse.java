package com.codemagi.burp.parser;

import com.codemagi.burp.Utils;
import java.io.*;
import java.util.*;

/**
 * Generic http response parser. Messages are of the general form:
 * <pre>
 * status_line
 * header: value
 * header: value
 * header: value
 * ...
 * </pre> where status_line is something like
 * <pre>HTTP/1.1 200 OK</pre>
 *
 * <p>
 * This class will parse all the header/value pairs and store them in a
 * ({@link java.util.LinkedHashMap}), and parse the first line as 'command'. The
 * <tt>LinkedHashMap</tt> will assure that an iterator will visit the fields in
 * the order they were originally sent/parsed.
 *
 * The body of the HTTP response is stored as-is in the 'body' member.
 *
 * KNOWN ISSUE: Some HTTP responses contain duplicate header names. This class
 * will replace duplicate headers in the order they are found. E.g. the value of
 * the second header with the same name will replace the first.
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class HttpResponse {

    //protected URL url;
    protected Integer responseCode;
    protected String responseReason;
    protected String version;
    protected String body;
    protected LinkedHashMap<String, String> headers = new LinkedHashMap<>();
    protected LinkedHashMap<String, String> sortedHeaders = null;

    /**
     * Private no-argument constructor is only used internally by static factory
     * methods.
     */
    private HttpResponse() {
    }

    /**
     * Constructor for creating an HttpMessage from a URL and an HTTP method.
     *
     * This method will create an HTTP/1.1 request with the URI passed in the
     * 'url' parameter. A 'Host' header will be set with the host portion of the
     * 'url' parameter
     *
     * @param responseCode The HTTP response code
     * @param responseReason The HTTP response message
     */
    public HttpResponse(Integer responseCode, String responseReason) {
        this.responseCode = responseCode;
        this.responseReason = responseReason;
        this.version = "HTTP/1.1";
    }

    public Integer getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(Integer responseCode) {
        this.responseCode = responseCode;
    }

    public String getResponseReason() {
        return responseReason;
    }

    public void setResponseReason(String responseReason) {
        this.responseReason = responseReason;
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

        sortedHeaders = new LinkedHashMap<>(headers.size());

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
     * Returns the map of HTTP headers contained in this message, in their
     * original order.
     *
     * @return A LinkedHashMap containing the HTTP headers
     */
    public LinkedHashMap getHeaders() {
        return headers;
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
     * Removes a header based on its name
     * @param name The name of the header to remove
     */
    public void removeHeader(String name) {
        sortedHeaders = null;
        headers.remove(name);
    }

    /**
     * Sets the Content-Length header to the current size of the response body
     *
     * @return The length of the body content
     */
    public int getContentLength() {
        int contentLength = Utils.noNulls(body).length();
        return contentLength;
    }

    public void setContentLength() {
        int contentLength = Utils.noNulls(body).length();
        setHeader("Content-Length", contentLength + "");
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
     * Parses a new HttpMessage using {@link #parse(InputStream)} with out as
     * null.
     *
     * @param in The InputStream to parse
     * @return An HttpMessage object parsed from the InputStream
     * @throws java.io.IOException Any IO Exceptions will be thrown
     */
    public static HttpResponse parseMessage(InputStream in) throws IOException {
        HttpResponse m = new HttpResponse();
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
    public static HttpResponse parseMessage(byte[] in) throws IOException {
        HttpResponse m = new HttpResponse();
        m.parse(new ByteArrayInputStream(in));
        return m;
    }

    public static HttpResponse parseMessage(String in) throws IOException {
        if (in != null) {
            return parseMessage(in.getBytes());
        }
        return new HttpResponse();
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
        BufferedReader bin = new BufferedReader(new InputStreamReader(in));
        String currLine = bin.readLine();

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
                split = new String[]{
                    split[0], ""
                };
            }

            String headerName = Utils.trim(split[0]);
            String headerValue = Utils.trim(split[1]);

            headers.put(headerName, headerValue);

            currLine = bin.readLine();
        }

        //parse the  body, if there is one
        StringBuilder bodyBuilder = new StringBuilder();
        int c;
        while ((c = bin.read()) != -1) {
            //Since c is an integer, cast it to a char. If it isn't -1, it will be in the correct range of char.
            bodyBuilder.append( (char)c ) ;  
        }
        this.body = bodyBuilder.toString();
    }

    private void parseCommand(String command) {
        if (Utils.isEmpty(command)) {
            return;
        }

        String[] parts = command.split(" ", 3);
        version = (parts.length > 0) ? parts[0] : "";
        responseCode = (parts.length > 1) ? Integer.parseInt(parts[1]) : 0;
        responseReason = (parts.length > 2) ? parts[2] : "";
    }

    @Override
    public String toString() {
        StringBuilder output = new StringBuilder(1024);

        //Add the command
        output.append(version).append(" ");
        output.append(responseCode).append(" ");
        output.append(responseReason).append("\r\n");

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
