/*
 * MessageDisplay.java
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
package org.rstudio.core.client;

import java.util.List;

import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.Focusable;

import org.rstudio.core.client.widget.*;
import org.rstudio.studio.client.common.GlobalDisplay;

public abstract class MessageDisplay
{
   // These constant values correspond to QMessageBox::Icon enum
   public final static int MSG_INFO = 1;
   public final static int MSG_WARNING = 2;
   public final static int MSG_ERROR = 3;
   public final static int MSG_QUESTION = 4;
   public final static int MSG_POPUP_BLOCKED = 0;

   public static class PromptWithOptionResult
   {
      public String input;
      public boolean extraOption;
   }
   
   public abstract void promptForText(String title,
                                      String label,
                                      String initialValue,
                                      OperationWithInput<String> operation);

   public abstract void promptForText(String title,
                                      String label,
                                      String initialValue,
                                      ProgressOperationWithInput<String> operation);
  
   public abstract void promptForText(String title,
                                      String label,
                                      String initialValue,
                                      int selectionStart,
                                      int selectionLength,
                                      String okButtonCaption,
                                      ProgressOperationWithInput<String> operation);

   public void promptForPassword(
         String title,
         String label,
         String initialValue,
         // Null or "" means don't show an extra option
         String rememberPasswordPrompt,
         boolean rememberByDefault,
         ProgressOperationWithInput<PromptWithOptionResult> okOperation,
         Operation cancelOperation)
   {
      promptForTextWithOption(title, 
                              label, 
                              initialValue, 
                              true,
                              rememberPasswordPrompt,
                              rememberByDefault,
                              okOperation,
                              cancelOperation);
   }
   
   public abstract void promptForTextWithOption(
         String title,
         String label,
         String initialValue,
         boolean showPasswordMask,
         // Null or "" means don't show an extra option
         String extraOption,
         boolean extraOptionDefault,
         ProgressOperationWithInput<PromptWithOptionResult> okOperation,
         Operation cancelOperation);

   public abstract void promptForInteger(
         String title,
         String label,
         Integer initialValue,
         ProgressOperationWithInput<Integer> okOperation,
         Operation cancelOperation);

   protected abstract DialogBuilder createDialog(int type,
                                                 String caption,
                                                 String message);

   public void showMessage(int type, String caption, String message)
   {
      createDialog(type, caption, message).showModal();
   }

   public void showMessage(int type,
                           String caption,
                           String message,
                           Operation dismissed)
   {
      createDialog(type, caption, message)
            .addButton("OK", dismissed)
            .showModal();
   }
      
   public void showMessage(int type,
                           String caption,
                           String message,
                           Operation dismissed,
                           String okLabel,
                           boolean includeCancel)
   {
      DialogBuilder dialog = createDialog(type, caption, message)
            .addButton(okLabel, dismissed);
      if (includeCancel)
         dialog.addButton("Cancel");
      dialog.showModal();
   }

   public void showMessage(int type,
                           String caption,
                           String message,
                           final Focusable focusAfter)
   {
      createDialog(type, caption, message)
      .addButton("OK", new Operation() {

         public void execute()
         {
            FocusHelper.setFocusDeferred(focusAfter);
         }
      })
      .showModal();
   }

   public void showMessage(int type,
                           String caption,
                           String message,
                           final CanFocus focusAfter)
   {
      createDialog(type, caption, message)
      .addButton("OK", new Operation() {

         public void execute()
         {
            FocusHelper.setFocusDeferred(focusAfter);
         }
      })
      .showModal();
   }

   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                Operation yesOperation,
                                boolean yesIsDefault)
   {
      createDialog(type, caption, message)
            .addButton("Yes", yesOperation)
            .addButton("No")
            .setDefaultButton(yesIsDefault ? 0 : 1)
            .showModal();
   }

   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                ProgressOperation yesOperation,
                                boolean yesIsDefault)
   {
      createDialog(type, caption, message)
            .addButton("Yes", yesOperation)
            .addButton("No")
            .setDefaultButton(yesIsDefault ? 0 : 1)
            .showModal();
   }

   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                boolean includeCancel,
                                Operation yesOperation,
                                Operation noOperation,
                                boolean yesIsDefault)
   {
      DialogBuilder dialog = createDialog(type, caption, message)
            .addButton("Yes", yesOperation)
            .addButton("No", noOperation)
            .setDefaultButton(yesIsDefault ? 0 : 1);
      if (includeCancel)
         dialog.addButton("Cancel");
      dialog.showModal();
   }

   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                boolean includeCancel,
                                final Operation yesOperation,
                                final Operation noOperation,
                                final Operation cancelOperation,
                                String yesLabel,
                                String noLabel,
                                boolean yesIsDefault)
   {
      DialogBuilder dialog = createDialog(type, caption, message)
            .addButton(yesLabel, yesOperation)
            .addButton(noLabel, noOperation)
            .setDefaultButton(yesIsDefault ? 0 : 1);
      if (includeCancel)
         dialog.addButton("Cancel", cancelOperation);
      dialog.showModal();
   }

   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                boolean includeCancel,
                                ProgressOperation yesOperation,
                                ProgressOperation noOperation,
                                boolean yesIsDefault)
   {
      showYesNoMessage(type, 
                       caption, 
                       message, 
                       includeCancel, 
                       yesOperation,
                       noOperation,
                       "Yes",
                       "No",
                       yesIsDefault);
   }
   
   public void showYesNoMessage(int type,
                                String caption,
                                String message,
                                boolean includeCancel,
                                ProgressOperation yesOperation,
                                ProgressOperation noOperation,
                                String yesLabel,
                                String noLabel,
                                boolean yesIsDefault)
   {
      DialogBuilder dialog = createDialog(type, caption, message)
            .addButton(yesLabel, yesOperation)
            .addButton(noLabel, noOperation)
            .setDefaultButton(yesIsDefault ? 0 : 1);
      if (includeCancel)
         dialog.addButton("Cancel");
      dialog.showModal();
   }
   
   public void showGenericDialog(int type,
                                 String caption,
                                 String message,
                                 List<String> buttonLabels,
                                 List<Operation> buttonOperations,
                                 int defaultButton)
   {
      DialogBuilder dialog = createDialog(type, caption, message);
      int numButtons = Math.min(buttonLabels.size(), buttonOperations.size());
      for (int i = 0; i < numButtons; i++)
      {
         dialog.addButton(buttonLabels.get(i),
                          buttonOperations.get(i));
      }
      dialog.setDefaultButton(defaultButton);
      dialog.showModal();
   }
   
   public void showErrorMessage(String caption, String message)
   {
      createDialog(MSG_ERROR, caption, message).showModal();
   }

   public void showErrorMessage(String caption,
                                String message,
                                Operation dismissed)
   {
      createDialog(MSG_ERROR, caption, message)
            .addButton("OK", dismissed)
            .showModal();
   }

   public void showErrorMessage(String caption,
                                String message,
                                Focusable focusAfter)
   {
      showMessage(MSG_ERROR, caption, message, focusAfter);
   }

   public void showErrorMessage(String caption,
                                String message,
                                CanFocus focusAfter)
   {
      showMessage(MSG_ERROR, caption, message, focusAfter);
   }
   
   public void showPopupBlockedMessage(Operation yesOperation)
   {
      showYesNoMessage(
            GlobalDisplay.MSG_POPUP_BLOCKED,
            "Popup Blocked",
            "We attempted to open an external browser window, but " +
            "the action was prevented by your popup blocker. You " +
            "can attempt to open the window again by pressing the " +
            "\"Try Again\" button below.\n\n" +
            "NOTE: To prevent seeing this message in the future, you " +
            "should configure your browser to allow popup windows " +
            "for " + Window.Location.getHostName() + ".",
            false,
            yesOperation,
            new Operation()
            {
               public void execute()
               {

               }
            },
            null,
            "Try Again",
            "Cancel",
            true);
   }
   
   public void showNotYetImplemented()
   {
      showMessage(MSG_INFO, 
                 "Not Yet Implemetned", 
                 "This feature has not yet been implemented.");
   }
}
