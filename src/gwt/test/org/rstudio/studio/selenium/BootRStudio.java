/*
 * BootRStudio.java
 *
 * Copyright (C) 2009-13 by RStudio, Inc.
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

package org.rstudio.studio.selenium;

import org.openqa.selenium.WebDriver;

import static org.junit.Assert.*;

import org.junit.Test; 

public class BootRStudio  {

   @Test
   public void testRStudioBoot() throws Exception {
       WebDriver driver = RStudioWebAppDriver.start();

       // Check the title of the page
       assertEquals(driver.getTitle(), "RStudio");

       // Close the browser
       RStudioWebAppDriver.stop();
   }
}
