/*
 * ErrorHandlerType.java
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

package org.rstudio.studio.client.common.debugging.model;

import com.google.gwt.core.client.JavaScriptObject;

public class ErrorHandlerType extends JavaScriptObject
{
   // Error handler types understood by the server. These values are persisted
   // in user settings, so their meaning must be preserved.
   public static final int ERRORS_MESSAGE   = 0;
   public static final int ERRORS_TRACEBACK = 1;
   public static final int ERRORS_BREAK     = 2;
   public static final int ERRORS_CUSTOM    = 3;
   public static final int ERRORS_NOTEBOOK  = 4;
   
   protected ErrorHandlerType() {}

   public final native int getType() /*-{
      return this.type;
   }-*/;   
}
