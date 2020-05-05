/*
 * TutorialInstaller.hpp
 *
 * Copyright (C) 2009-12 by RStudio, Inc.
 *
 */

#ifndef SESSION_PRESENTATION_TUTORIAL_INSTALLER_HPP
#define SESSION_PRESENTATION_TUTORIAL_INSTALLER_HPP

#include <string>
#include <vector>

#include <core/FilePath.hpp>

#include "Tutorial.hpp"

namespace rstudio {
namespace session {
namespace modules { 
namespace presentation {

void installTutorial(const core::FilePath& tutorialPath,
                     const Tutorial& tutorial,
                     const core::FilePath& targetPath);

} // namespace presentation
} // namespace modules
} // namespace session
} // namespace rstudio

#endif // SESSION_PRESENTATION_TUTORIAL_INSTALLER_HPP
