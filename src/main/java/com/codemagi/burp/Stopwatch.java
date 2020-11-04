package com.codemagi.burp;

/*
 *  Copyright 2008 CodeMagi, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * The Stopwatch class is used for timing operations.
 *
 * <code>
 *     Stopwatch timer = new Stopwatch();
 *     timer.start();
 *     //do some task that you want to time
 *     timer.stop();
 *     long elapsedTime = timer.getElapsedTime();
 * </code>
 *
 * @version 1.0
 * @author	August Detlefsen for CodeMagi, Inc.
 */
public class Stopwatch {

    private long startTime = 0;
    private long endTime = 0;
    private long elapsedTime = 0;

    private long lapStartTime = 0;
    private long lapEndTime = 0;
    private long lapElapsedTime = 0;

    /**
     * Starts the stopwatch.
     */
    public void start() {
        startTime = System.nanoTime();
        lapStartTime = startTime;
    }

    /**
     * Stops the stopwatch.
     */
    public void stop() {
        endTime = System.nanoTime();
        lapEndTime = endTime;

        computeElapsedTime();
    }

    /**
     * Records "lap time" while the stopwatch continues to run.
     */
    public void lap() {
        lapEndTime = System.nanoTime();
        computeLapTime();
    }

    private void computeElapsedTime() {
        elapsedTime = endTime - startTime;
    }

    private void computeLapTime() {
        lapElapsedTime = lapEndTime - lapStartTime;
        lapStartTime = lapEndTime;
    }

    /**
     * Returns the time (in milliseconds) elapsed between start and stop
     *
     * @return Elapsed time between start and stop
     */
    public long getElapsedTime() {
        return elapsedTime / 1000000;
    }

    /**
     * Returns the time (in milliseconds) elapsed for the current lap
     *
     * @return Elapsed time for the current lap
     */
    public long getLapTime() {
        return lapElapsedTime / 1000000;
    }

    /**
     * Returns the time (in nanoseconds) elapsed between start and stop
     *
     * @return Elapsed time between start and stop
     */
    public long getElapsedTimeNanos() {
        return elapsedTime;
    }

    /**
     * Returns the time (in nanoseconds) elapsed for the current lap
     *
     * @return Elapsed time for the current lap
     */
    public long getLapTimeNanos() {
        return lapElapsedTime;
    }

}
