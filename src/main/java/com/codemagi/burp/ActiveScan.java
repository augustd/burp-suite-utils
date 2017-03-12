package com.codemagi.burp;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.codemagi.burp.ScanIssue;
import java.net.URL;
import java.util.Collections;

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
public abstract class ActiveScan extends BaseExtender implements IScannerCheck {

	protected static List<MatchRule> rules = new ArrayList<MatchRule>();

	//private Map<String,Pattern> rules = new HashMap<String,Pattern>();
	@Override
	protected void initialize() {
		//set the extension Name
		extensionName = "Base Active Scan";

		//call the subclass initializer
		initActiveScan();

		// register the extension as a custom scanner check
		callbacks.registerScannerCheck(this);
	}

	/**
	 * Implement this method to perform passive scan specific initialization.
	 */
	protected abstract void initActiveScan();

	/**
	 * Implement the getIssueName method to return the name of an issue to be
	 * added to Burp's Scanner tab.
	 *
	 * @param baseRequestResponse The request response pair being analyzed
	 * @param matches A list of matches found by the scanner
	 * @param requestOffsets A list of integers marking start and stop points of
	 * matches in requests
	 * @param responseOffsets A list of integers marking start and stop points
	 * of matches in responses
	 * @return The scan issue to be added.
	 */
	protected abstract IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> requestOffsets, List<int[]> responseOffsets);

	/**
	 * Add a new match rule to the scan
	 *
	 * @param newRule match rule to add
	 */
	protected void addMatchRule(MatchRule newRule) {
		rules.add(newRule);
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		List<ScannerMatch> matches = new ArrayList<>();
		List<IScanIssue> issues = new ArrayList<>(1);

		//get the URL of the requst
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		callbacks.printOutput("Doing active scan: " + url.toString());

		//iterate through rules and check for matches
		for (MatchRule rule : rules) {

			// compile a request containing our injection test in the insertion point
			byte[] testBytes = rule.getTest().getBytes();
			byte[] checkRequest = insertionPoint.buildRequest(testBytes);

			// issue the request
			IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
					baseRequestResponse.getHttpService(), checkRequest);

			//get the response
			String response = helpers.bytesToString(checkRequestResponse.getResponse());

			// look for offsets of our active check grep string
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

			// report the issues ------------------------
			if (!matches.isEmpty()) {
				Collections.sort(matches); //matches must be in order

				// get the offsets of the payload within the request, for in-UI highlighting
				List<int[]> requestHighlights = new ArrayList<>(1);
				requestHighlights.add(insertionPoint.getPayloadOffsets(testBytes));

				//get the offsets of scanner matches in the response
				List<int[]> responseHighlights = new ArrayList<>(1);
				for (ScannerMatch match : matches) {
					callbacks.printOutput("Processing match: " + match);
					callbacks.printOutput("    start: " + match.getStart() + " end: " + match.getEnd() + " full match: " + match.getFullMatch() + " group: " + match.getMatchGroup());
					//add a marker for code highlighting
					responseHighlights.add(new int[]{match.getStart(), match.getEnd()});
				}

				// report the issue
				issues.add(getScanIssue(checkRequestResponse, matches, requestHighlights, responseHighlights));
			}
		}

		if (issues.size() > 0) {
			return issues;
		} else {
			return null;
		}

	}

	/**
	 * This method is called when multiple issues are reported for the same URL
	 * path by the same extension-provided check. The value we return from this
	 * method determines how/whether Burp consolidates the multiple issues to
	 * prevent duplication.
	 *
	 * Since the issue name is sufficient to identify our issues as different,
	 * if both issues have the same name, only report the existing issue
	 * otherwise report both issues
	 *
	 * @param existingIssue
	 * @param newIssue
	 * @return
	 */
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
			callbacks.printOutput("DUPLICATE ISSUE! Consolidating...");
			return -1;
		} else {
			return 0;
		}
	}

}
