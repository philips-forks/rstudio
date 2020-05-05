/*
 * CompilePdfPrefs.java
 *
 * Copyright (C) 2009-12 by RStudio, Inc.
 *
 * Unless you have received this program directly from RStudio pursuant
 * to the terms of a commercial license agreement with RStudio, then
 * this program is licensed to you under the terms of version 3 of the
 * GNU Affero General Public License. This program is distributed WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTY, INCLUDING THOSE OF NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Please refer to the
 * AGPL (http://www.gnu.org/licenses/agpl-3.0.txt) for more details.
 *
 */
package org.rstudio.studio.client.workbench.prefs.model;

import com.google.gwt.core.client.JavaScriptObject;

public class CompilePdfPrefs extends JavaScriptObject
{
   protected CompilePdfPrefs() {}

   public static final native CompilePdfPrefs create(boolean cleanOutput,
                                                     boolean enableShellEscape) /*-{
      var prefs = new Object();
      prefs.clean_output = cleanOutput;
      prefs.enable_shell_escape = enableShellEscape;
      return prefs ;
   }-*/;
   
   public native final boolean getCleanOutput() /*-{
      return this.clean_output;
   }-*/;
   
   public native final boolean getEnableShellEscape() /*-{
      return this.enable_shell_escape;
   }-*/;
}