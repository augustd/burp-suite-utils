/*
 * Copyright 2018 adetlefsen.
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

import burp.IParameter;

/**
 *
 * @author adetlefsen
 */
public class Parameter implements IParameter {

    private byte type;
    private String name;
    private String value;
    private String filename;
    private String contentType;
    private int nameStart = -1;
    private int nameEnd = -1;
    private int valueStart = -1;
    private int valueEnd = -1;
    
    public Parameter(String name, String value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Used to explicitly create a multipart parameter. Automatically sets the 
     * type attribute to IParameter.PARAM_MULTIPART_ATTR. 
     * 
     * @param name
     * @param value
     * @param filename
     * @param contentType 
     */
    public Parameter(String name, String value, String filename, String contentType) {
        this.name = name;
        this.value = value;
        this.filename = filename;
        this.contentType = contentType;
        this.type = IParameter.PARAM_MULTIPART_ATTR;
    }
    
    @Override
    public byte getType() {
        return type;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    public String getFilename() {
        return filename;
    }

    public String getContentType() {
        return contentType;
    }

    @Override
    public int getNameStart() {
        return nameStart;
    }

    @Override
    public int getNameEnd() {
        return nameEnd;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
    
}
