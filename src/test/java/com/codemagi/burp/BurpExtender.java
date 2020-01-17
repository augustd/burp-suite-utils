/*
 * Copyright 2020 adetlefsen.
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
import static org.mockito.Mockito.mock;

/**
 *
 * @author adetlefsen
 */
public class BurpExtender extends BaseExtender {

    private static BurpExtender instance;

	public BurpExtender() {
		callbacks = mock(IBurpExtenderCallbacks.class);
		registerExtenderCallbacks(callbacks);
		initialize();
	}
	
	@Override
	protected void initialize() {
		instance = this;
	}
	
}
