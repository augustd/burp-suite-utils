package com.codemagi.burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import java.net.URL;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class ScanIssue implements IScanIssue, Comparable<ScanIssue> {

	private final IHttpService httpService;
	private final URL url;
	private final IHttpRequestResponse[] httpMessages;
	private final String name;
	private final String detail;
	private final String severity;
	private final String confidence;

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
	
	public ScanIssue(IScanIssue existing) {
		this.httpService = existing.getHttpService();
		this.url = existing.getUrl();
		this.httpMessages = existing.getHttpMessages();
		this.name = existing.getIssueName();
		this.detail = existing.getIssueDetail();
		this.severity = existing.getSeverity();
		this.confidence = existing.getConfidence();
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

	@Override
	public int compareTo(ScanIssue o) {
		return getIssueDetail().compareTo(o.getIssueDetail());
	}
	
	@Override
    public int hashCode() {
        int nameCode = name.hashCode();
		int descCode = (detail == null) ? 0 : detail.hashCode();
        return 31 * nameCode + descCode;
    }

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final ScanIssue other = (ScanIssue) obj;
		if (!Objects.equals(this.name, other.name)) {
			return false;
		}
		if (!Objects.equals(this.detail, other.detail)) {
			return false;
		}
		return true;
	}

}
