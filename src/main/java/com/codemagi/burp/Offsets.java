/*
 * Copyright 2021 augustd.
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

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class Offsets {
    private Integer start;
    private Integer end;

    public Offsets(Integer start, Integer end) {
        this.start = start;
        this.end = end;
    }

    public Integer getStart() {
        return start;
    }

    public void setStart(Integer start) {
        this.start = start;
    }

    public Integer getEnd() {
        return end;
    }

    public void setEnd(Integer end) {
        this.end = end;
    }

    /**
     * Return true if this set of Offsets overlaps the other set passed in. 
     * 
     * @param other Another Offsets instance to compare against
     * @return true if this set of Offsets overlaps the other set passed in.
     */
    public boolean overlaps(Offsets other) {
        if (other == null) return false; 
        
        return (this.start <= other.getEnd() && other.getStart() <= this.end);
    }
    
    /**
     * Combine two sets of Offsets into one overlapping set. 
     * 
     * @param other Another Offsets instance to combine with 
     * @return An Offsets instance which combines the start/stop points of both instances
     */
    public Offsets combine(Offsets other) {
        if (other == null) return this;
        
        return new Offsets(Math.min(start, other.getStart()), Math.max(end, other.getEnd()));
    }
    
    /**
     * Retrieve the start/stop points as an int[] array. 
     * 
     * @return An array of int suitable for passing into a Burp IScanIssue
     */
    public int[] toArray() {
        int[] output = {start, end};
        return output;
    }
}
