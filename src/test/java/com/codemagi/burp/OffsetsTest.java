/*
 * Copyright 2021 august.
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
public class OffsetsTest {
    
    Offsets a = new Offsets(10, 15);
    Offsets b = new Offsets(20, 25);
    Offsets c = new Offsets(12, 17);
    Offsets d = new Offsets(8, 13);
    Offsets e = new Offsets(5, 20);
    
    public OffsetsTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void testOverlap() {
        assertFalse(a.overlaps(b));
        assertFalse(b.overlaps(a));
        
        assertTrue(a.overlaps(c));
        assertTrue(c.overlaps(a));
        
        assertTrue(a.overlaps(d));
        assertTrue(d.overlaps(a));
    
        assertTrue(a.overlaps(e));
        assertTrue(e.overlaps(a));
        
        assertTrue(b.overlaps(e));
        assertTrue(e.overlaps(b));
    }
    
    @Test
    public void testCombine() {
        Offsets product = a.combine(c);
        assertEquals(new Integer(10), product.getStart());
        assertEquals(new Integer(17), product.getEnd());
    }
}
