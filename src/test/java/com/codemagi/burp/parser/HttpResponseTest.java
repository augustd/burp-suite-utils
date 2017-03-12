/*
 * Copyright 2016 august.
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
package com.codemagi.burp.parser;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author august
 */
public class HttpResponseTest {
    
    HttpResponse responseToTest; 
    
    public HttpResponseTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
        try {
            responseToTest = HttpResponse.parseMessage("HTTP/1.1 201 Created\n" +
				"Date: Thu, 23 Feb 2017 23:16:17 GMT\n" +
				"Content-Type: application/json\n" +
				"Content-Length: 21\n" +
				"Connection: close\n" +
				"Vary: Origin\n" +
				"Cache-Control: max-age=0\n" +
				"Pragma: no-cache\n" +
				"Expires: Thu, 23 Feb 2017 23:16:17 GMT\n" +
				"X-Content-Type-Options: no-sniff\n" +
				"Strict-Transport-Security: max-age=31536000; includeSubDomains;\n" +
				"Cache-Control: no-cache, no-store, must-revalidate\n" +
				"Pragma: no-cache\n" +
				"X-Response-Time: 4.134\n" +
				"\n" +
				"{\n" +
				"  \"status\" : \"OK\"\n" +
				"}");
        } catch (IOException ex) {
            Logger.getLogger(HttpResponseTest.class.getName()).log(Level.SEVERE, null, ex);
        }
		
		System.out.println("-------------------");
		System.out.println(responseToTest.getBody());
		System.out.println("-------------------");
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getMethod method, of class HttpRequest.
     */
    @Test
    public void testGetResponseCode() {
        System.out.println("getResponseCode");
        Integer result = responseToTest.getResponseCode();
        assertEquals(new Integer(201), result);
    }

    /**
     * Test of getPath method, of class HttpRequest.
     */
    @Test
    public void testGetResponseReason() {
        System.out.println("getResponseReason");
        String result = responseToTest.getResponseReason();
        assertEquals("Created", result);
    }

    /**
     * Test of getVersion method, of class HttpRequest.
     */
    @Test
    public void testGetVersion() {
        System.out.println("getVersion");
        String result = responseToTest.getVersion();
        assertEquals("HTTP/1.1", result);
    }

    /**
     * Test of getBody method, of class HttpRequest.
     */
    @Test
    public void testGetBody() {
        System.out.println("getBody");
        String result = responseToTest.getBody();
        assertEquals("{\n  \"status\" : \"OK\"\n}", result);
    }

}
