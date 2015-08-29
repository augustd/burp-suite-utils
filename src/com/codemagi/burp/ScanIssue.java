package com.codemagi.burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import java.net.URL;
import java.util.List;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class ScanIssue implements IScanIssue {
    
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public ScanIssue(
	    IHttpService httpService,
	    URL url,
	    IHttpRequestResponse[] httpMessages,
	    String name,
	    String detail,
	    String severity,
	    String confidence) {
	this.httpService = httpService;
	this.url = url;
	this.httpMessages = httpMessages;
	this.name = name;
	this.detail = detail;
	this.severity = severity;
	this.confidence = confidence;
    }
    
    public ScanIssue(
	    IHttpRequestResponse baseRequestResponse, 
	    IExtensionHelpers helpers,
	    IBurpExtenderCallbacks callbacks,
	    List<int[]> offsets,
	    String name,
	    String detail,
	    String severity,
	    String confidence) {
	
	this.httpService = baseRequestResponse.getHttpService();
	this.url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	this.httpMessages = new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, offsets)};
	this.name = name;
	this.detail = detail;
	this.severity = severity;
	this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
	return url;
    }

    @Override
    public String getIssueName() {
	return name;
    }

    @Override
    public int getIssueType() {
	return 0;
    }

    @Override
    public String getSeverity() {
	return severity;
    }

    @Override
    public String getConfidence() {
	return confidence;
    }

    @Override
    public String getIssueBackground() {
	return null;
    }

    @Override
    public String getRemediationBackground() {
	return null;
    }

    @Override
    public String getIssueDetail() {
	return detail;
    }

    @Override
    public String getRemediationDetail() {
	return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
	return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
	return httpService;
    }

}
