/*
 * ConsoleProgressWidget.java
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
package org.rstudio.studio.client.workbench.views.vcs.common;

import org.rstudio.studio.client.common.shell.ShellDisplay;
import org.rstudio.studio.client.common.shell.ShellWidget;
import org.rstudio.studio.client.workbench.views.source.editors.text.AceEditor;

public class ConsoleProgressWidget extends ShellWidget implements ShellDisplay
{
   public ConsoleProgressWidget()
   {
      super(new AceEditor(), null);
      getEditor().setInsertMatching(false);
   }
   
   private AceEditor getEditor()
   {
      return input_;
   }
}
