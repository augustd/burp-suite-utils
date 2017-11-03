package com.codemagi.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public abstract class BaseExtender implements IBurpExtender {

	protected String extensionName = "Base Extension";

	/**
	 * The settingsNamespace should be overridden by subclasses. It is appended
	 * to settings which will be saved in the Burp state.
	 */
	protected String settingsNamespace = "BE_";
	protected static IBurpExtenderCallbacks callbacks;
	protected static IExtensionHelpers helpers;
	protected OutputStream stdout;
	protected OutputStream stderr;
	
	private static IBurpExtender instance;

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
		
		//put this into the local instance variable
		instance = this;

		//initialize the extension
		initialize();

		// set our extension name
		callbacks.setExtensionName(extensionName);

		callbacks.printOutput("Loaded " + extensionName);
	}

	/**
	 * Implement the initialize method to perform any initialization tasks for
	 * this extension. This method will be called in registerExtenderCallbacks
	 * after the callbacks and helpers have been loaded.
	 */
	protected abstract void initialize();

	public static IBurpExtender getInstance() {
        return instance;
    }
        
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
    
    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

	/**
	 * Print a stack trace to the extender errors UI
	 *
	 * @param e Exception to print stack trace for.
	 */
	public void printStackTrace(Exception e) {
		e.printStackTrace(new PrintStream(stderr));
	}

	public String getSettingsNamespace() {
		return settingsNamespace;
	}

}
