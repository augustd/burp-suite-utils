package com.monikamorrow.burp;

import burp.IBurpExtenderCallbacks;

/**
 * @author Monika Morrow Original URL:
 * https://github.com/monikamorrow/Burp-Suite-Extension-Examples/tree/master/GUI%20Utils
 */
public class ToolsScopeComponent extends javax.swing.JPanel {

	IBurpExtenderCallbacks mCallbacks;
	
	private static final String SETTING_PROXY = "O_TOOL_PROXY";
	private static final String SETTING_REPEATER = "O_TOOL_REPEATER";
	private static final String SETTING_SCANNER = "O_TOOL_SCANNER";
	private static final String SETTING_INTRUDER = "O_TOOL_INTRUDER";
	private static final String SETTING_SEQUENCER = "O_TOOL_SEQUENCER";
	private static final String SETTING_SPIDER = "O_TOOL_SPIDER";

	/**
	 * Creates new form BurpSuiteTab
	 *
	 * @param callbacks For UI Look and Feel
	 */
	public ToolsScopeComponent(IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;

		initComponents();

		mCallbacks.customizeUiComponent(jCheckBoxProxy);
		mCallbacks.customizeUiComponent(jCheckBoxRepeater);
		mCallbacks.customizeUiComponent(jCheckBoxScanner);
		mCallbacks.customizeUiComponent(jCheckBoxIntruder);
		mCallbacks.customizeUiComponent(jCheckBoxSequencer);
		mCallbacks.customizeUiComponent(jCheckBoxSpider);

		restoreSavedSettings();
	}

	/**
	 * Allows the enabling/disabling of UI tool selection elements, not every
	 * tool makes sense for every extension
	 *
	 * @param tool
	 * @param enabled
	 */
	public void setEnabledToolConfig(int tool, boolean enabled) {
		switch (tool) {
			case IBurpExtenderCallbacks.TOOL_PROXY:
				jCheckBoxProxy.setEnabled(enabled);
				break;
			case IBurpExtenderCallbacks.TOOL_REPEATER:
				jCheckBoxRepeater.setEnabled(enabled);
				break;
			case IBurpExtenderCallbacks.TOOL_SCANNER:
				jCheckBoxScanner.setEnabled(enabled);
				break;
			case IBurpExtenderCallbacks.TOOL_INTRUDER:
				jCheckBoxIntruder.setEnabled(enabled);
				break;
			case IBurpExtenderCallbacks.TOOL_SEQUENCER:
				jCheckBoxSequencer.setEnabled(enabled);
				break;
			case IBurpExtenderCallbacks.TOOL_SPIDER:
				jCheckBoxSpider.setEnabled(enabled);
				break;
			default:
				break;
		}
	}

	/**
	 * Allows the developer to set the default value for selected tools, not
	 * every tool makes sense for every extension
	 *
	 * @param tool
	 * @param enabled
	 */
	public void setToolDefault(int tool, boolean enabled) {
		switch (tool) {
			case IBurpExtenderCallbacks.TOOL_PROXY:
				if (mCallbacks.loadExtensionSetting(SETTING_PROXY) == null) {
					jCheckBoxProxy.setSelected(enabled);
				}
				break;
			case IBurpExtenderCallbacks.TOOL_REPEATER:
				if (mCallbacks.loadExtensionSetting(SETTING_REPEATER) == null) {
					jCheckBoxRepeater.setSelected(enabled);
				}
				break;
			case IBurpExtenderCallbacks.TOOL_SCANNER:
				if (mCallbacks.loadExtensionSetting(SETTING_SCANNER) == null) {
					jCheckBoxScanner.setSelected(enabled);
				}
				break;
			case IBurpExtenderCallbacks.TOOL_INTRUDER:
				if (mCallbacks.loadExtensionSetting(SETTING_INTRUDER) == null) {
					jCheckBoxIntruder.setSelected(enabled);
				}
				break;
			case IBurpExtenderCallbacks.TOOL_SEQUENCER:
				if (mCallbacks.loadExtensionSetting(SETTING_SEQUENCER) == null) {
					jCheckBoxProxy.setSelected(enabled);
				}
				break;
			case IBurpExtenderCallbacks.TOOL_SPIDER:
				if (mCallbacks.loadExtensionSetting(SETTING_SPIDER) == null) {
					jCheckBoxSpider.setSelected(enabled);
				}
				break;
			default:
				break;
		}
	}

	/**
	 * Returns true if the requested tool is selected in the GUI
	 *
	 * @param tool
	 * @return whether the selected tool is selected
	 */
	public boolean isToolSelected(int tool) {
		boolean selected = false;
		switch (tool) {
			case IBurpExtenderCallbacks.TOOL_PROXY:
				selected = jCheckBoxProxy.isSelected() && jCheckBoxProxy.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_REPEATER:
				selected = jCheckBoxRepeater.isSelected() && jCheckBoxRepeater.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_SCANNER:
				selected = jCheckBoxScanner.isSelected() && jCheckBoxScanner.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_INTRUDER:
				selected = jCheckBoxIntruder.isSelected() && jCheckBoxIntruder.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_SEQUENCER:
				selected = jCheckBoxSequencer.isSelected() && jCheckBoxSequencer.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_SPIDER:
				selected = jCheckBoxSpider.isSelected() && jCheckBoxSpider.isEnabled();
				break;
			case IBurpExtenderCallbacks.TOOL_TARGET:
				break;
			default:
				break;
		}
		return selected;
	}

	/**
	 * Save all configured settings
	 */
	public void saveSettings() {
		mCallbacks.saveExtensionSetting(SETTING_PROXY, setSetting(jCheckBoxProxy.isSelected()));
		mCallbacks.saveExtensionSetting(SETTING_REPEATER, setSetting(jCheckBoxRepeater.isSelected()));
		mCallbacks.saveExtensionSetting(SETTING_SCANNER, setSetting(jCheckBoxScanner.isSelected()));
		mCallbacks.saveExtensionSetting(SETTING_INTRUDER, setSetting(jCheckBoxIntruder.isSelected()));
		mCallbacks.saveExtensionSetting(SETTING_SEQUENCER, setSetting(jCheckBoxSequencer.isSelected()));
		mCallbacks.saveExtensionSetting(SETTING_SPIDER, setSetting(jCheckBoxSpider.isSelected()));
	}

	/**
	 * Restores any found saved settings
	 */
	public void restoreSavedSettings() {
		if (mCallbacks.loadExtensionSetting(SETTING_PROXY) != null) {
			jCheckBoxProxy.setSelected(getSetting(SETTING_PROXY));
		}
		if (mCallbacks.loadExtensionSetting(SETTING_REPEATER) != null) {
			jCheckBoxRepeater.setSelected(getSetting(SETTING_REPEATER));
		}
		if (mCallbacks.loadExtensionSetting(SETTING_SCANNER) != null) {
			jCheckBoxScanner.setSelected(getSetting(SETTING_SCANNER));
		}
		if (mCallbacks.loadExtensionSetting(SETTING_INTRUDER) != null) {
			jCheckBoxIntruder.setSelected(getSetting(SETTING_INTRUDER));
		}
		if (mCallbacks.loadExtensionSetting(SETTING_SEQUENCER) != null) {
			jCheckBoxSequencer.setSelected(getSetting(SETTING_SEQUENCER));
		}
		if (mCallbacks.loadExtensionSetting(SETTING_SPIDER) != null) {
			jCheckBoxSpider.setSelected(getSetting(SETTING_SPIDER));
		}
	}

	/**
	 * Get the boolean value of the requested setting
	 *
	 * @param name
	 * @return whether the setting was selected
	 */
	private boolean getSetting(String name) {
		return mCallbacks.loadExtensionSetting(name).equals("ENABLED") == true;
	}

	private String setSetting(boolean value) {
		return value ? "ENABLED" : "DISABLED";
	}

	/**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jCheckBoxProxy = new javax.swing.JCheckBox();
        jCheckBoxRepeater = new javax.swing.JCheckBox();
        jCheckBoxScanner = new javax.swing.JCheckBox();
        jCheckBoxIntruder = new javax.swing.JCheckBox();
        jCheckBoxSequencer = new javax.swing.JCheckBox();
        jCheckBoxSpider = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(229, 137, 0));
        jLabel1.setText("Tools Scope");

        jCheckBoxProxy.setSelected(true);
        jCheckBoxProxy.setText("Proxy");
        jCheckBoxProxy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxProxyActionPerformed(evt);
            }
        });

        jCheckBoxRepeater.setSelected(true);
        jCheckBoxRepeater.setText("Repeater");
        jCheckBoxRepeater.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxRepeaterActionPerformed(evt);
            }
        });

        jCheckBoxScanner.setText("Scanner");
        jCheckBoxScanner.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxScannerActionPerformed(evt);
            }
        });

        jCheckBoxIntruder.setText("Intruder");
        jCheckBoxIntruder.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxIntruderActionPerformed(evt);
            }
        });

        jCheckBoxSequencer.setText("Sequencer");
        jCheckBoxSequencer.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxSequencerActionPerformed(evt);
            }
        });

        jCheckBoxSpider.setText("Spider");
        jCheckBoxSpider.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxSpiderActionPerformed(evt);
            }
        });

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(229, 137, 0));

        jLabel4.setText("Select the tools that this extention will act on:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jCheckBoxProxy)
                            .addComponent(jCheckBoxRepeater)
                            .addComponent(jCheckBoxScanner))
                        .addGap(22, 22, 22)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jCheckBoxSpider)
                            .addComponent(jCheckBoxSequencer)
                            .addComponent(jCheckBoxIntruder)))
                    .addComponent(jLabel1)
                    .addComponent(jLabel4))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBoxProxy)
                    .addComponent(jCheckBoxIntruder))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBoxRepeater)
                    .addComponent(jCheckBoxSequencer))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBoxScanner)
                    .addComponent(jCheckBoxSpider))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel3))
        );

        jLabel1.getAccessibleContext().setAccessibleDescription("");
    }// </editor-fold>//GEN-END:initComponents

    private void jCheckBoxProxyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxProxyActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxProxyActionPerformed

    private void jCheckBoxRepeaterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxRepeaterActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxRepeaterActionPerformed

    private void jCheckBoxScannerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxScannerActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxScannerActionPerformed

    private void jCheckBoxIntruderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxIntruderActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxIntruderActionPerformed

    private void jCheckBoxSequencerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxSequencerActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxSequencerActionPerformed

    private void jCheckBoxSpiderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxSpiderActionPerformed
		saveSettings();
    }//GEN-LAST:event_jCheckBoxSpiderActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox jCheckBoxIntruder;
    private javax.swing.JCheckBox jCheckBoxProxy;
    private javax.swing.JCheckBox jCheckBoxRepeater;
    private javax.swing.JCheckBox jCheckBoxScanner;
    private javax.swing.JCheckBox jCheckBoxSequencer;
    private javax.swing.JCheckBox jCheckBoxSpider;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    // End of variables declaration//GEN-END:variables

}
