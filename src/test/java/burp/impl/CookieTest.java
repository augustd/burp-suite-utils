/*
 * Copyright 2018 augustd.
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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author adetlefsen
 */
public class CookieTest {
    
    Cookie cookieToTest; 
    
    public CookieTest() {
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
            cookieToTest = Cookie.parseCookie(" oid=00F60023000NtVr;Path=/;Domain=joebob.jimbob.com;Expires=Fri, 27 Dec 2019 17:15:15 GMT;Max-Age=63072000;Secure");
        } catch (ParseException ex) {
            Logger.getLogger(CookieTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getName method, of class Cookie.
     */
    @Test
    public void testGetName() {
        System.out.println("getName");
        String expResult = "oid";
        String result = cookieToTest.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getValue method, of class Cookie.
     */
    @Test
    public void testGetValue() {
        System.out.println("getValue");
        String expResult = "00F60023000NtVr";
        String result = cookieToTest.getValue();
        assertEquals(expResult, result);
    }

    /**
     * Test of getDomain method, of class Cookie.
     */
    @Test
    public void testGetDomain() {
        System.out.println("getDomain");
        String expResult = "joebob.jimbob.com";
        String result = cookieToTest.getDomain();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPath method, of class Cookie.
     */
    @Test
    public void testGetPath() {
        System.out.println("getPath");
        String expResult = "/";
        String result = cookieToTest.getPath();
        assertEquals(expResult, result);
    }

    /**
     * Test of getExpiration method, of class Cookie.
     */
    @Test
    public void testGetExpiration() {
        try {
            System.out.println("getExpiration");
            SimpleDateFormat format = new SimpleDateFormat("MM dd yyyy HH mm ss X");
            Date expResult = format.parse("12 27 2019 17 15 15 +00:00");
            Date result = cookieToTest.getExpiration();
            assertEquals(expResult, result);
        } catch (ParseException ex) {
            //go buy a lotto ticket
        }
    }

    /**
     * Test of getMaxAge method, of class Cookie.
     */
    @Test
    public void testGetMaxAge() {
        System.out.println("getMaxAge");
        Long expResult = 63072000l;
        Long result = cookieToTest.getMaxAge();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSecure method, of class Cookie.
     */
    @Test
    public void testGetSecure() {
        System.out.println("getSecure");
        Boolean expResult = true;
        Boolean result = cookieToTest.getSecure();
        assertEquals(expResult, result);
    }

    /**
     * Test of getHttpOnly method, of class Cookie.
     */
    @Test
    public void testGetHttpOnly() {
        System.out.println("getHttpOnly");
        Boolean expResult = false;
        Boolean result = cookieToTest.getHttpOnly();
        assertEquals(expResult, result);
    }

}
