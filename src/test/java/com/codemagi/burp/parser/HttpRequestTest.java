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
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
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
public class HttpRequestTest {
    
    HttpRequest requestToTest; 
    
    public HttpRequestTest() {
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
            requestToTest = HttpRequest.parseMessage("GET /shape/user/customers/v1/3F38BC45474838A4E0540010E056A2AC/contactsV2?_=1477287417967 HTTP/1.1\n"
                    + "Host: www.stubhub.com\n"
                    + "Connection: close\n"
                    + "x-csrf-token: wRq7uZV6R5yoKneHGIV1SwShIb587z350hGtzlLCNM8YTpegOI8w9IbV20KQ2wkc26nhzKAvA2GiTcdHslcdsmfz7CO0tkwtHobk2CRAe44=\n"
                    + "Accept-Language: en-us\n"
                    + "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36\n"
                    + "Content-Type: application/json\n"
                    + "Accept: application/json\n"
                    + "X-Requested-With: XMLHttpRequest\n"
                    + "X-Distil-Ajax: dybdqqdcwwxvaztstd\n"
                    + "com-stubhub-dye-path: 88ccf713115e45a991fd15ab371f5ec4,3709d25e61f84b6b9447d4f812adfef5\n"
                    + "Referer: https://www.stubhub.com/my/profile/\n"
                    + "Accept-Encoding: gzip, deflate, sdch, br\n"
                    + "Cookie: TLTSID=510133A0956110955DA3F04498B8F11E; __uvt=; xdVisitorId=124E2U5hWSsmYkAvOikQMUjAORR_Sa_QgSn4CYvkx4aUzik9562; roost-isopen=false; _br_uid_2=uid%3D5022415566262%3Av%3D11.8%3Ats%3D1476815594950%3Ahc%3D8; akavpau_ddos_us_domain=1476916882~id=8895aabb86dfa7c7d4c2df00c65f545c; D_SID=67.164.46.210:YhP6dmoOvsh6ttuFxvK+ulrNKne7dwl96ii+vBarRfI; AMCV_1AEC46735278551A0A490D45%40AdobeOrg=1304406280%7CMCIDTS%7C17099%7CMCMID%7C22839376381354285132418624970913047347%7CMCAAMLH-1477420390%7C9%7CMCAAMB-1477892111%7CNRX38WO0n5BH8Th-nqAG_A%7CMCAID%7CNONE; session:userGUID=3F38BC45474838A4E0540010E056A2AC; session_userGUID=3F38BC45474838A4E0540010E056A2AC; track_session_userGUID=3F38BC45474838A4E0540010E056A2AC; session_uAuthenticated=1; session:CSRFtoken=wRq7uZV6R5yoKneHGIV1SwShIb587z350hGtzlLCNM8YTpegOI8w9IbV20KQ2wkc26nhzKAvA2GiTcdHslcdsmfz7CO0tkwtHobk2CRAe44=; session_CSRFtoken=wRq7uZV6R5yoKneHGIV1SwShIb587z350hGtzlLCNM8YTpegOI8w9IbV20KQ2wkc26nhzKAvA2GiTcdHslcdsmfz7CO0tkwtHobk2CRAe44=; SH_UT=Di5JOQAl64vbL1y5ikAZnP%2BQHUbfrX2onlx%2Fs%2B2loCSX4oBWieI6oAgJbf4JpcAX6NUsL%2BAZFdgH8toxhHTlIRthHK6cSCxq6EaATR58cLR67YdEI%2FcSlRrJ8XkSqxtVEtqKsKz%2Fzy4R3JdbKXCSo9tU3e%2FFFY235pOePRLX58PPnmdTxNqXZq0Q6dpIFuVcHy3pL71WDFri7%2FgviRPQSoXZNdGM3C%2Fz6U0Nw90vTd1aTmS9Gn5DzyCZjiog8RU%2B; session:contactGUID=C9WcuhprhoWOzv5t; session_contactGUID=C9WcuhprhoWOzv5t; session_loginStatus=true; session_login_type=stubhub; roost-flyout=false; STUB_SESS=filler%7E%5E%7E0%7Capp_token%7E%5E%7EBImXAmYKv7MZjdJqQiBaUOcoa2HXA3Bgr5nl%2Fie9i9Y%3D%7E%5E%7E10%2F24%2F2016; SH_AT=1XNOHCPxzhOmYfQsadRFfX%2FOMRCZ0KKzhzQg%2BzAtaxxW5pfv1Rx11KOIF7aMprwAh7RNWYYcMwhTtmcZsl4mA4949B12RE0HNaxJ3BCiHA8%3D; mbox=PC#1476815590217-725364.28_72#1511501819|session#1477287311123-208095#1477289279; D_PID=469F0452-18FF-3E05-8072-566D9785BE96; D_IID=36915B2D-D498-3ED4-97F2-CE2D8EB77D17; D_UID=3CABCE26-0333-33A7-9A8F-553C9CE58CAB; D_HID=wt6rWxlMA4ovFJqILdCcDqLFB0hkEzf3V8ckBKyACVA; D_ZID=A3101A9A-548B-391E-8D8F-7D571D120D01; D_ZUID=827DA0CA-6FA1-3827-9735-0ED99EAFE9A3; S_ACCT=stubhub; SH_VI=0f380dfcece04a8a876eee8835301cca; s_pers=%20currentCTC%3DC12289x486%7C1479411195133%3B%20s_cpm%3D%255B%255B%27C12289x486%27%252C%271476815595137%27%255D%255D%7C1634581995137%3B%20currentCVP%3DC12289x486%7C1479411195139%3B%20s_ev41%3D%255B%255B%2710%252F18%252F2016%2525206%25253A33%252520PM%27%252C%271476815595141%27%255D%255D%7C1634581995141%3B%20s_dfa%3Dstubhub%7C1477289217995%3B%20s_vs%3D1%7C1477289218614%3B%20s_nr%3D1477287418624-Repeat%7C1511415418624%3B; s_sess=%20sessionCTC%3DC12289x486%3B%20sessionreferrer%3Dhttps%253A%252F%252Fwww.google.com%252F%3B%20s_campaign%3DC12289x486%3B%20s_cc%3Dtrue%3B%20s_cpc%3D0%3B%20s_sq%3D%3B; atgRecVisitorId=124E2U5hWSsmYkAvOikQMUjAORR_Sa_QgSn4CYvkx4aUzik9562; atgRecSessionId=SPX1L36Ka5O6icfRFrUinUhjaRfWYNYc7DIKxSNU8rVJDvl02dKu!-1231746196!959570671; fsr.s={\"v2\":-2,\"v1\":1,\"rid\":\"de35431-94594988-351e-a2d3-a7f6e\",\"ru\":\"https://www.google.com/\",\"r\":\"www.google.com\",\"st\":\"\",\"cp\":{\"Unified_StubHub\":\"N\",\"TLSessionID\":\"510133A0956110955DA3F04498B8F11E\"},\"to\":4.7,\"c\":\"https://www.stubhub.com/my/profile/\",\"pv\":25,\"lc\":{\"d3\":{\"v\":25,\"s\":true}},\"cd\":3,\"f\":1477287417754,\"sd\":3}; uvts=5B2JX8ru0ymZuBtN; roost-notes-read=%7B%22data%22%3A%5B%5D%7D; session:sessionId=9C5B937F708345BD91B5791AF1FBC171; session_sessionId=9C5B937F708345BD91B5791AF1FBC171; TLTHID=E361A9C099AB10996913ED86149BD762; DC=lvs01; session:loginStatus=1\n");
        } catch (IOException ex) {
            Logger.getLogger(HttpRequestTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getMethod method, of class HttpRequest.
     */
    @Test
    public void testGetMethod() {
        System.out.println("getMethod");
        String result = requestToTest.getMethod();
        assertEquals("GET", result);
    }

    /**
     * Test of getPath method, of class HttpRequest.
     */
    @Test
    public void testGetPath() {
        System.out.println("getPath");
        String result = requestToTest.getPath();
        assertEquals("/shape/user/customers/v1/3F38BC45474838A4E0540010E056A2AC/contactsV2", result);
    }

    /**
     * Test of getVersion method, of class HttpRequest.
     */
    @Test
    public void testGetVersion() {
        System.out.println("getVersion");
        String result = requestToTest.getVersion();
        assertEquals("HTTP/1.1", result);
    }

    /**
     * Test of getBody method, of class HttpRequest.
     */
    @Test
    public void testGetBody() {
        System.out.println("getBody");
        String result = requestToTest.getBody();
        assertEquals("", result);
    }

    /**
     * Test of convertToPost method, of class HttpRequest.
     */
    /*
    @Test
    public void testConvertToPost() {
        System.out.println("convertToPost");
        HttpRequest instance = null;
        instance.convertToPost();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of getHeadersSorted method, of class HttpRequest.
     */
    /*
    @Test
    public void testGetHeadersSorted() {
        System.out.println("getHeadersSorted");
        HttpRequest instance = null;
        LinkedHashMap expResult = null;
        LinkedHashMap result = instance.getHeadersSorted();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of setHeader method, of class HttpRequest.
     */
    /*
    @Test
    public void testSetHeader() {
        System.out.println("setHeader");
        String name = "";
        String value = "";
        HttpRequest instance = null;
        String expResult = "";
        String result = instance.setHeader(name, value);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of getHeader method, of class HttpRequest.
     */
    /*
    @Test
    public void testGetHeader() {
        System.out.println("getHeader");
        String name = "";
        HttpRequest instance = null;
        String expResult = "";
        String result = instance.getHeader(name);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of getCookies method, of class HttpRequest.
     */
    @Test
    public void testGetCookies() {
        System.out.println("getCookies");
        List<Cookie> result = requestToTest.getCookies();
        assertEquals(43, result.size());
    }

    /**
     * Test of setCookies method, of class HttpRequest.
     */
    /*
    @Test
    public void testSetCookies() {
        System.out.println("setCookies");
        List<Cookie> cookies = null;
        HttpRequest instance = null;
        instance.setCookies(cookies);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of setParameter method, of class HttpRequest.
     */
    /*
    @Test
    public void testSetParameter() {
        System.out.println("setParameter");
        String name = "";
        String value = "";
        HttpRequest instance = null;
        String expResult = "";
        String result = instance.setParameter(name, value);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */

    /**
     * Test of getParametersSorted method, of class HttpRequest.
     */
    /*
    @Test
    public void testGetParametersSorted() {
        System.out.println("getParametersSorted");
        HttpRequest instance = null;
        LinkedHashMap expResult = null;
        LinkedHashMap result = instance.getParametersSorted();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    */
    
}
