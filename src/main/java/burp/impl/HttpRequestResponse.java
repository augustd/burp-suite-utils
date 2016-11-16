/*
 * Copyright 2016 augustd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package burp.impl;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * Basic implementation of the IHttpRequestResponse interface.
 * 
 * @author augustd
 */
public class HttpRequestResponse implements IHttpRequestResponse {

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    /*
     * Default no-arg constructor creates a completely empty object.
     */
    public HttpRequestResponse() {
    }
    
    /**
     * Constructs an HttpRequestResponse initializing all fields from the passed Object. 
     * 
     * @param ihrr 
     */
    public HttpRequestResponse(IHttpRequestResponse ihrr) {
        this.request = ihrr.getRequest();
        this.response = ihrr.getResponse();
        this.comment = ihrr.getComment();
        this.highlight = ihrr.getHighlight();
        this.httpService = ihrr.getHttpService();
    }
    
    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        this.request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        this.response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
    
}
