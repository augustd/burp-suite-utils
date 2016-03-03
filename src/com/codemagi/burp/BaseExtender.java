package com.codemagi.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 *
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public abstract class BaseExtender implements IBurpExtender {
    
    protected String extensionName = "Base Extension";
    
    /**
     * The settingsNamespace should be overridden by subclasses. It is appended to settings which will be saved in the Burp state. 
     */
    protected String settingsNamespace = "BE_";
    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;
    protected OutputStream stdout;
    protected OutputStream stderr;

    /**
     * implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

	// keep a reference to our callbacks object
	this.callbacks = callbacks;
	
	// obtain an extension helpers object
	helpers = callbacks.getHelpers();
	
	//get the output streams for info and error messages
	stdout = callbacks.getStdout();
	stderr = callbacks.getStderr();
	
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
    
    /**
     * Print a stack trace to the extender errors UI
     */
    public void printStackTrace(Exception e) {
        e.printStackTrace(new PrintStream(stderr));
    }

    public String getSettingsNamespace() {
        return settingsNamespace;
    }
    
}
