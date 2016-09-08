package com.codemagi.burp;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class Utils {

    public static final Charset UTF8 = Charset.forName("UTF-8");

    /**
     * Block constructor by design
     */
    private Utils() {
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

}
