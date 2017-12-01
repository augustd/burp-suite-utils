package com.codemagi.burp;

import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Utils {

    public static final Charset UTF8 = Charset.forName("UTF-8");
    public static final Map<Integer,String> TOOLS = new HashMap<>();
    static {
        TOOLS.put(1, "Suite");
        TOOLS.put(2, "Target");
        TOOLS.put(4, "Proxy");
        TOOLS.put(8, "Spider");
        TOOLS.put(16, "Scanner");
        TOOLS.put(32, "Intruder");
        TOOLS.put(64, "Repeater");
        TOOLS.put(128, "Sequencer");
        TOOLS.put(256, "Decoder");
        TOOLS.put(512, "Comparer");
        TOOLS.put(1024, "Extender");
    }

    /**
     * Block constructor by design
     */
    private Utils() {
    }
    
    /**
     * Returns the human-readable tool name for the passed tool flag
     */
    public static String getToolName(int toolFlag) {
        return noNulls(TOOLS.get(toolFlag));
    }
    
    /**
     * Returns the user-selected text in the passed array.
     * 
     * @param message  The array of bytes to get the selection from
     * @param offsets  The offsets within the array that indicate the start and end points of the selection
     * @return A String representing the selected bytes. If offsets is null or if both values are the same, "" is returned.
     */
    public static String getSelection(byte[] message, int[] offsets) {
        if (offsets == null || message == null) return "";
        
        if (offsets.length < 2 || offsets[0] == offsets[1]) return "";
        
        byte[] selection = Arrays.copyOfRange(message, offsets[0], offsets[1]);
        
        return new String(selection);
    }
    
    public static ICookie getCookieByName(IResponseInfo responseInfo, String cookieName) {
        List<ICookie> cookies = responseInfo.getCookies();
        for (ICookie cookie : cookies) {
            if (cookie.getName().equals(cookieName)) return cookie;
        }
        return null;
    }
    
    public static String replaceGroup(Pattern regex, String source, int groupToReplace, String replacement) {
        return replaceGroup(regex, source, groupToReplace, 1, replacement);
    }

    public static String replaceGroup(Pattern regex, String source, int groupToReplace, int groupOccurrence, String replacement) {
        Matcher m = regex.matcher(source);
        for (int i = 0; i < groupOccurrence; i++) {
            if (!m.find()) {
                return source; // pattern not met, may also throw an exception here
            }
        }
        return new StringBuilder(source)
                .replace(m.start(groupToReplace), m.end(groupToReplace), replacement)
                .toString();
    }


    /**
     * Determines if a string is null or empty
     *
     * @param value string to test
     * @return       <code>true</code> if the string is empty or null;
     * <code>false</code> otherwise
     */
    public static boolean isEmpty(String value) {
	return (value == null || value.trim().length() == 0);
    }

    /**
     * Trims all leading and trailing whitespace from a String.
     *
     * @param valueIn The String to trim
     * @return String The input String trimmed of leading and trailing
     * whitespace, or ""
     */
    public static String trim(String valueIn) {
	//make sure they entered SOMETHING
	if (isEmpty(valueIn)) {
	    return "";
	}

	return valueIn.trim();
    }

    /**
     * Converts null Strings to empty String ("").
     * 
     * @param test String to convert
     * @return The original String, or "" if the input is null
     */
    public static String noNulls(String test) {
	return noNulls(test, test, "");
    }

    /**
     * Outputs the String output if the test String is not empty, otherwise
     * outputs default
     *
     * @param test String to test for emptyness
     * @param output String to output if the test String is not empty
     * @param defaultOutput String to output if the test String is empty
     * @return Object Empty String if the input was null, the input unchanged
     * otherwise
     */
    public static String noNulls(String test, String output, String defaultOutput) {
	if (isEmpty(test)) {
	    return defaultOutput;
	}

	return output;
    }
    
    /**
     * Converts null Objects to empty String ("").
     *
     * @param input The object to test for null-ness
     * @return Object Empty String if the input was null, the input unchanged
     * otherwise
     */
    public static Object noNulls(Object input) {
	if (input == null) {
	    return "";
	}

	return input;
    }

    public static String toHex(byte[] data) {
	StringBuilder sb = new StringBuilder(data.length * 2);
	for (int i = 0; i < data.length; i++) {
	    String hex = Integer.toHexString(data[i]);
	    if (hex.length() == 1) {
		// Append leading zero.
		sb.append("0");
	    } else if (hex.length() == 8) {
		// Remove ff prefix from negative numbers.
		hex = hex.substring(6);
	    }
	    sb.append(hex);
	}
	return sb.toString().toLowerCase(Locale.getDefault());
    }

    public static String toHex(String data) {
	if (data == null) {
	    return "";
	}
	return toHex(data.getBytes());

    }
    
    public static byte[] getResponseBody(byte[] response, IExtensionHelpers helpers) {
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        int offset = responseInfo.getBodyOffset();
        return Arrays.copyOfRange(response, offset, response.length);
    }
    
    public static <T>T getFirst(List<T> list) {
        if (list == null || list.isEmpty()) return null;
        return list.get(0);
    }

    /**
     * Returns the contents of an ASCII file as a List of Strings.
     * 
     * This method throws any fileIO errors.
     *
     * @param sFileName Full file path.
     * @return String[] String array containing the contents of the file, one
     * element per line
     * @throws Exception Any fileIO errors
     */
    public static List<String> getFileAsLines(String sFileName) throws Exception {

	FileInputStream fIn = null;
	BufferedReader fileReader = null;

	try {
	    //open the file 
	    fIn = new FileInputStream(sFileName);
	    fileReader = new BufferedReader(new InputStreamReader(fIn));

	    //create a Vector for output
	    ArrayList<String> output = new ArrayList<String>();

	    //read the file line by line, append lines to the Vector
	    String line = null;

	    while ((line = fileReader.readLine()) != null) {
		output.add(line);
	    }

	    return output;

	} catch (Exception e) {

	    throw e;

	} finally {

	    fIn.close();
	    fileReader.close();

	}

    }

    /**
     * URL decodes an input String using the UTF-8 character set
     * (IExtensionHelpers class uses LATIN-1)
     *
     * @param input The String to decode
     * @return The URL-decoded String
     */
    public static String urlDecode(String input) {
        try {
            return URLDecoder.decode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }

    /**
     * URL encodes an input String using the UTF-8 character set
     * (IExtensionHelpers class uses LATIN-1)
     *
     * @param input The String to encode
     * @return The URL-encoded String
     */
    public static String urlEncode(String input) {
        try {
            return URLEncoder.encode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }

}
