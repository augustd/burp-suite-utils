package com.codemagi.burp;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;

/**
 * This class abstracts everything needed to create a custom passive scan. 
 * Extend this class to create a passive scan: 
 * <ol>
 * <li>Set the extension name</li>
 * <li>Add MatchRules</li>
 * <li>implement getScanIssue() to return a custom scan issue</li>
 * </ol>
 * 
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public abstract class PassiveScan extends BaseExtender implements IScannerCheck {

    protected static List<MatchRule> rules = new ArrayList<MatchRule>();
    
    @Override
    protected void initialize() {
	//set the extension Name
	extensionName = "Base Passive Scan";
        
        //set the settings namespace (subclasses should override this)
        settingsNamespace = "PS_";
	
	//call the subclass initializer
	initPassiveScan();

	// register the extension as a custom scanner check
	callbacks.registerScannerCheck(this);
    }
    
    /**
     * Implement this method to perform passive scan specific initialization. 
     */
    protected abstract void initPassiveScan();
    
    /**
     * Implement the getScanIssue method to return the name of an issue to be added to Burp's Scanner tab.
     * 
     * @param baseRequestResponse  The request response pair being analyzed
     * @param matches  A list of matches found by the scanner
     * @param startStop  A list of integers marking start and stop points of matches 
     * @return The scan issue to be added. 
     */
    protected abstract IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop);

    /**
     * Add a new match rule to the scan
     * 
     * @param newRule match rule to add
     */
    public void addMatchRule(MatchRule newRule) {
	rules.add(newRule);
    }
    
    /**
     * Remove match rule from the scan
     * 
     * @param index Index of the match rule to remove
     */
    public void removeMatchRule(int index) {
	rules.remove(index);
    }
    
    /**
     * Clear all match rules from the scan
     */
    public void clearMatchRules() {
        rules.clear();
    }
    
    /**
     * Get an existing match rule of the scan. 
     * 
     * If no match rule exists at the specified index, this method returns null.
     * 
     * @param index Index of the match rule to return
     * @return The match rule at the specified index, or null if none exists
     */
    public MatchRule getMatchRule(int index) {
        if (index < rules.size()) {
            return rules.get(index);
        } 
        return null;
    }
    
    /**
     * implement IScannerCheck
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
	List<ScannerMatch> matches = new ArrayList<>();
	List<IScanIssue> issues = new ArrayList<>();
	
	//get the URL of the requst
	URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	callbacks.printOutput("Doing passive scan: " + url.toString());
	
	//get the body of the response
	byte[] responseBytes = baseRequestResponse.getResponse();
	String response = helpers.bytesToString(responseBytes);
	
	//iterate through rules and check for matches
	for (MatchRule rule : rules) {
	    Matcher matcher = rule.getPattern().matcher(response);
	    while (matcher.find()) {
		//get the actual match
		String group;
		if (rule.getMatchGroup() != null) {
		    group = matcher.group(rule.getMatchGroup());
		} else {
		    group = matcher.group();
		}
		
		callbacks.printOutput("start: " + matcher.start() + " end: " + matcher.end() + " group: " + group);
		matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule));
	    }
	}
	
	// report the issues ------------------------
	if (!matches.isEmpty()) {
	    Collections.sort(matches); //matches must be in order

	    //get the offsets of scanner matches
	    List<int[]> startStop = new ArrayList<int[]>(1);
	    for (ScannerMatch match : matches) {
		callbacks.printOutput("Processing match: " + match);
		callbacks.printOutput("    start: " + match.getStart() + " end: " + match.getEnd() + " match: " + match.getMatch() + " match: " + match.getMatch());
		//add a marker for code highlighting
		startStop.add(new int[]{match.getStart(), match.getEnd()});
	    }
	    
	    issues.add(getScanIssue(baseRequestResponse, matches, startStop));
	    
	    callbacks.printOutput("issues: " + issues.size());
	    return issues;
	}
	
	return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
	return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
	// This method is called when multiple issues are reported for the same URL
	// path by the same extension-provided check. The value we return from this
	// method determines how/whether Burp consolidates the multiple issues
	// to prevent duplication
	//
	// Since the issue name is sufficient to identify our issues as different,
	// if both issues have the same name, only report the existing issue
	// otherwise report both issues
	if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
	    callbacks.printOutput("DUPLICATE ISSUE! Consolidating...");
	    return -1;
	} else {
	    return 0;
	}
    }
    
}
