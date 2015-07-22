package com.codemagi.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import java.io.OutputStream;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public abstract class BaseExtender implements IBurpExtender {
    
    protected String extensionName = "Base Extension";
    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected OutputStream stdout;

    /**
     * implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

	// keep a reference to our callbacks object
	this.callbacks = callbacks;
	
	// obtain an extension helpers object
	helpers = callbacks.getHelpers();
	
	//get the stdout stream for info messages
	stdout = callbacks.getStdout();
	
	//initialize the extension
	initialize();
	
	// set our extension name
	callbacks.setExtensionName(extensionName);
	
	callbacks.printOutput("Loaded " + extensionName);
    }

    /**
     * Implement the initialize method to perform any initialization tasks for this extension. 
     * This method will be called in registerExtenderCallbacks after the callbacks and helpers have been loaded.
     */
    protected abstract void initialize();
    
}
