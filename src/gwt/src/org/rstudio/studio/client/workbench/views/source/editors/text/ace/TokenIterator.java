/*
 * TokenIterator.java
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
package org.rstudio.studio.client.workbench.views.source.editors.text.ace;

import com.google.gwt.core.client.JavaScriptObject;

public class TokenIterator extends JavaScriptObject
{
   public static native TokenIterator create(EditSession session,
                                             int initialRow,
                                             int initialColumn) /*-{
      var TokenIterator = $wnd.require('ace/token_iterator').TokenIterator;
      return new TokenIterator(session, initialRow, initialColumn);
   }-*/;

   public static native TokenIterator create(EditSession session) /*-{
      var TokenIterator = $wnd.require('ace/token_iterator').TokenIterator;
      return new TokenIterator(session);
   }-*/;
   
   protected TokenIterator() {}
   
   public native final TokenIterator clone() /*-{
      return this.clone();
   }-*/;

   public native final Token stepForward() /*-{
      return this.stepForward();
   }-*/;

   public native final Token stepBackward() /*-{
      return this.stepBackward();
   }-*/;

   public native final Token getCurrentToken() /*-{
      return this.getCurrentToken();
   }-*/;
   
   public native final Position getCurrentTokenPosition() /*-{
      return this.getCurrentTokenPosition();
   }-*/;

   public native final int getCurrentTokenRow() /*-{
      return this.getCurrentTokenRow();
   }-*/;

   public native final int getCurrentTokenColumn() /*-{
      return this.getCurrentTokenColumn();
   }-*/;
   
   public native final boolean fwdToMatchingToken() /*-{
      return this.fwdToMatchingToken();
   }-*/;
   
   public native final boolean bwdToMatchingToken() /*-{
      return this.bwdToMatchingToken();
   }-*/;
   
   public native final void tokenizeUpToRow(int row) /*-{
      this.tokenizeUpToRow(row);
   }-*/;
   
   public native final Token moveToPosition(Position pos) /*-{
      return this.moveToPosition(pos);
   }-*/;
   
   public final Token moveToPosition(int row, int column)
   {
      return moveToPosition(Position.create(row, column));
   }
   
   public final native Token moveToEndOfRow() /*-{
      return this.moveToEndOfRow();
   }-*/;
}
