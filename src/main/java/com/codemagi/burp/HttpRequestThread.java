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
package com.codemagi.burp;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.impl.HttpService;

import java.util.concurrent.TimeUnit;

/**
 * Used to issue HTTP requests with a timeout:
 * <code>
 *     //issue request, with timeout
 *     HttpService service = new HttpService(targetUrl);
 *     HttpRequestThread requestThread = new HttpRequestThread(service, request.getBytes(), callbacks);
 *     try {
 *         TimeLimitedCodeBlock.runWithTimeout(requestThread, 60, TimeUnit.SECONDS);
 *     } catch (Exception ex) {
 *         BurpExtender.printStackTrace(ex);
 *     }
 * </code>
 *
 * @author adetlefsen
 */
public class HttpRequestThread extends Thread {

    private final String host;
    private final int port;
    private final boolean useHttps;
    private final byte[] request;
    private final IBurpExtenderCallbacks callbacks;
    private byte[] response;

    public HttpRequestThread(String host, int port, boolean useHttps, byte[] request, IBurpExtenderCallbacks callbacks) {
        this.host = host;
        this.port = port;
        this.useHttps = useHttps;
        this.request = request;
        this.callbacks = callbacks;
    }
    
    public HttpRequestThread(IHttpService service, byte[] request, IBurpExtenderCallbacks callbacks) {
        this.host = service.getHost();
        this.port = service.getPort();
        this.useHttps = HttpService.PROTOCOL_HTTPS.equalsIgnoreCase(service.getProtocol());
        this.request = request;
        this.callbacks = callbacks;
    }
    
    @Override
    public void run() {
        synchronized(this){
            response = callbacks.makeHttpRequest(host, port, useHttps, request);
            notify();
        }
    }

    public byte[] getResponse() {
        return response;
    }

}
