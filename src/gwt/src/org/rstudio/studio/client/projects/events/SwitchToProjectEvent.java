/*
 * SwitchToProjectEvent.java
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
package org.rstudio.studio.client.projects.events;

import com.google.gwt.event.shared.GwtEvent;

public class SwitchToProjectEvent extends GwtEvent<SwitchToProjectHandler>
{
   public static final GwtEvent.Type<SwitchToProjectHandler> TYPE =
      new GwtEvent.Type<SwitchToProjectHandler>();
   
   public SwitchToProjectEvent(String project)
   {
      this(project, false);
   }
   
   public SwitchToProjectEvent(String project, boolean forceSaveAll)
   {
      project_ = project;
      forceSaveAll_ = forceSaveAll;
   }
   
   public String getProject()
   {
      return project_;
   }
   
   public boolean getForceSaveAll()
   {
      return forceSaveAll_;
   }
   
   @Override
   protected void dispatch(SwitchToProjectHandler handler)
   {
      handler.onSwitchToProject(this);
   }

   @Override
   public GwtEvent.Type<SwitchToProjectHandler> getAssociatedType()
   {
      return TYPE;
   }
   
   private final String project_;
   private final boolean forceSaveAll_;
}
