/*
 * SessionConsoleProcessInfo.cpp
 *
 * Copyright (C) 2009-17 by RStudio, Inc.
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

#include <session/SessionConsoleProcessInfo.hpp>

#include <core/system/Process.hpp>
#include <core/system/System.hpp>
#include <core/text/TermBufferParser.hpp>

#include <session/SessionConsoleProcessPersist.hpp>
#include <session/SessionModuleContext.hpp>

using namespace rstudio::core;

namespace rstudio {
namespace session {
namespace console_process {

const int kDefaultMaxOutputLines = 500;
const int kDefaultTerminalMaxOutputLines = 1000; // xterm.js scrollback constant
const int kNoTerminal = 0; // terminal sequence number for a non-terminal
const int kNewTerminal = -1; // new terminal, sequence number yet to be determined
const size_t kOutputBufferSize = 8192;

ConsoleProcessInfo::ConsoleProcessInfo()
   : terminalSequence_(kNoTerminal), allowRestart_(false),
     interactionMode_(InteractionNever), maxOutputLines_(kDefaultMaxOutputLines),
     showOnOutput_(false), outputBuffer_(kOutputBufferSize), childProcs_(true),
     altBufferActive_(false), shellType_(TerminalShell::DefaultShell),
     channelMode_(Rpc), cols_(system::kDefaultCols), rows_(system::kDefaultRows),
     restarted_(false), autoClose_(DefaultAutoClose), zombie_(false), trackEnv_(false)
{
   // When we retrieve from outputBuffer, we only want complete lines. Add a
   // dummy \n so we can tell the first line is a complete line.
   outputBuffer_.push_back('\n');
}

// The constant values in the initializer list (i.e. those not supplied as arguments
// to the constructor) should match the constants set in the client
// ConsoleProcessInfo.createNewTerminalInfo constructor. A new terminal can be
// created from the client side via the UI using the client-side constructor, or on
// the server-side via the R API (e.g. terminalCreate) which uses this C++ constructor.
ConsoleProcessInfo::ConsoleProcessInfo(
         const std::string& caption,
         const std::string& title,
         const std::string& handle,
         const int terminalSequence,
         TerminalShell::TerminalShellType shellType,
         bool altBufferActive,
         const core::FilePath& cwd,
         int cols, int rows, bool zombie, bool trackEnv)
   : caption_(caption), title_(title), handle_(handle),
     terminalSequence_(terminalSequence), allowRestart_(true),
     interactionMode_(InteractionAlways), maxOutputLines_(kDefaultTerminalMaxOutputLines),
     showOnOutput_(false), outputBuffer_(kOutputBufferSize), childProcs_(true),
     altBufferActive_(altBufferActive), shellType_(shellType),
     channelMode_(Rpc), cwd_(cwd), cols_(cols), rows_(rows), restarted_(false),
     autoClose_(DefaultAutoClose), zombie_(zombie), trackEnv_(trackEnv)
{
}

ConsoleProcessInfo::ConsoleProcessInfo(
         const std::string& caption,
         InteractionMode mode,
         int maxOutputLines)
   : caption_(caption), terminalSequence_(kNoTerminal), allowRestart_(false),
     interactionMode_(mode), maxOutputLines_(maxOutputLines),
     showOnOutput_(false), outputBuffer_(kOutputBufferSize), childProcs_(true),
     altBufferActive_(false), shellType_(TerminalShell::DefaultShell),
     channelMode_(Rpc), cols_(system::kDefaultCols), rows_(system::kDefaultRows),
     restarted_(false), autoClose_(DefaultAutoClose), zombie_(false), trackEnv_(false)
{
}

void ConsoleProcessInfo::ensureHandle()
{
   if (handle_.empty())
      handle_ = core::system::generateShortenedUuid();
}

void ConsoleProcessInfo::setExitCode(int exitCode)
{
   exitCode_.reset(exitCode);
}

void ConsoleProcessInfo::resetExitCode()
{
   exitCode_.reset();
}

void ConsoleProcessInfo::appendToOutputBuffer(const std::string &str)
{
   // For modal console procs, store terminal output directly in the
   // ConsoleProcInfo INDEX
   if (getTerminalSequence() == kNoTerminal)
   {
      std::copy(str.begin(), str.end(), std::back_inserter(outputBuffer_));
      return;
   }

   // For terminal tabs, store in a separate file, first removing any
   // output targeting the alternate terminal buffer.
   std::string mainBufferStr =
         core::text::stripSecondaryBuffer(str, &altBufferActive_);

   console_persist::appendToOutputBuffer(handle_, mainBufferStr);
}

void ConsoleProcessInfo::appendToOutputBuffer(char ch)
{
   outputBuffer_.push_back(ch);
}

std::string ConsoleProcessInfo::getSavedBufferChunk(
      int requestedChunk, bool* pMoreAvailable) const
{
   // We read the entire buffer into memory to return a given chunk. This is
   // ok for our current usage pattern, where the buffer-size is bounded
   // to a certain number of lines and is infrequently reloaded (only upon
   // browser refresh or reloading a session). If this pattern becomes
   // more frequent and/or we support much larger buffers, we'd want to
   // reconsider this implementation.

   // Read buffer (trims to maxOutputLines_ when chunk zero is requested)
   std::string buffer = console_persist::getSavedBuffer(
            handle_,
            requestedChunk == 0 ? maxOutputLines_ : 0);

   *pMoreAvailable = false;

   // Common case, entire buffer fits in chunk zero
   if (requestedChunk == 0 && (buffer.length() <= kOutputBufferSize))
      return buffer;

   // Chunk requested past end of buffer?
   if (requestedChunk * kOutputBufferSize >= buffer.length())
      return std::string();

   // Otherwise return substring for the chunk (substr doesn't mind if you ask
   // for more characters than are available in the string, as long as the
   // starting position is within the string)
   std::string chunk = buffer.substr(
            requestedChunk * kOutputBufferSize, kOutputBufferSize);
   if (requestedChunk * kOutputBufferSize + chunk.length() < buffer.length())
      *pMoreAvailable = true;

   return chunk;
}

std::string ConsoleProcessInfo::getFullSavedBuffer() const
{
   // Read buffer (trims to maxOutputLines_)
   return console_persist::getSavedBuffer(handle_, maxOutputLines_);
}

int ConsoleProcessInfo::getBufferLineCount() const
{
   return console_persist::getSavedBufferLineCount(handle_, maxOutputLines_);
}

std::string ConsoleProcessInfo::bufferedOutput() const
{
   boost::circular_buffer<char>::const_iterator pos =
         std::find(outputBuffer_.begin(), outputBuffer_.end(), '\n');

   std::string result;
   if (pos != outputBuffer_.end())
      pos++;
   std::copy(pos, outputBuffer_.end(), std::back_inserter(result));
   // Will be empty if the buffer was overflowed by a single line
   return result;
}

void ConsoleProcessInfo::deleteLogFile(bool lastLineOnly) const
{
   console_persist::deleteLogFile(handle_, lastLineOnly);
}

void ConsoleProcessInfo::deleteEnvFile() const
{
   console_persist::deleteEnvFile(handle_);
}

core::json::Object ConsoleProcessInfo::toJson() const
{
   json::Object result;
   result["handle"] = handle_;
   result["caption"] = caption_;
   result["show_on_output"] = showOnOutput_;
   result["interaction_mode"] = static_cast<int>(interactionMode_);
   result["max_output_lines"] = maxOutputLines_;
   result["buffered_output"] = bufferedOutput();
   if (exitCode_)
      result["exit_code"] = *exitCode_;
   else
      result["exit_code"] = json::Value();

   // newly added in v1.1
   result["terminal_sequence"] = terminalSequence_;
   result["allow_restart"] = allowRestart_;
   result["title"] = title_;
   result["child_procs"] = childProcs_;
   result["shell_type"] = static_cast<int>(shellType_);
   result["channel_mode"] = static_cast<int>(channelMode_);
   result["channel_id"] = channelId_;
   result["alt_buffer"] = altBufferActive_;
   result["cwd"] = module_context::createAliasedPath(cwd_);
   result["cols"] = cols_;
   result["rows"] = rows_;
   result["restarted"] = restarted_;
   result["autoclose"] = static_cast<int>(autoClose_);
   result["zombie"] = zombie_;
   result["track_env"] = trackEnv_;

   return result;
}

boost::shared_ptr<ConsoleProcessInfo> ConsoleProcessInfo::fromJson(core::json::Object& obj)
{
   boost::shared_ptr<ConsoleProcessInfo> pProc(new ConsoleProcessInfo());

   json::Value handle = obj["handle"];
   if (!handle.is_null())
      pProc->handle_ = handle.get_str();
   json::Value caption = obj["caption"];
   if (!caption.is_null())
      pProc->caption_ = caption.get_str();

   json::Value showOnOutput = obj["show_on_output"];
   if (!showOnOutput.is_null())
      pProc->showOnOutput_ = showOnOutput.get_bool();
   else
      pProc->showOnOutput_ = false;

   json::Value mode = obj["interaction_mode"];
   if (!mode.is_null())
      pProc->interactionMode_ = static_cast<InteractionMode>(mode.get_int());
   else
      pProc->interactionMode_ = InteractionNever;

   json::Value maxLines = obj["max_output_lines"];
   if (!maxLines.is_null())
      pProc->maxOutputLines_ = maxLines.get_int();
   else
      pProc->maxOutputLines_ = kDefaultMaxOutputLines;

   json::Value bufferedOutputValue = obj["buffered_output"];
   if (!bufferedOutputValue.is_null())
   {
      std::string bufferedOutput = bufferedOutputValue.get_str();
      std::copy(bufferedOutput.begin(), bufferedOutput.end(),
                std::back_inserter(pProc->outputBuffer_));
   }
   json::Value exitCode = obj["exit_code"];
   if (exitCode.is_null())
      pProc->exitCode_.reset();
   else
      pProc->exitCode_.reset(exitCode.get_int());

   pProc->terminalSequence_ = obj["terminal_sequence"].get_int();
   pProc->allowRestart_ = obj["allow_restart"].get_bool();

   json::Value title = obj["title"];
   if (!title.is_null())
      pProc->title_ = title.get_str();

   pProc->childProcs_ = obj["child_procs"].get_bool();
   int shellTypeInt = obj["shell_type"].get_int();
   pProc->shellType_ =
      static_cast<TerminalShell::TerminalShellType>(shellTypeInt);
   int channelModeInt = obj["channel_mode"].get_int();
   pProc->channelMode_ = static_cast<ChannelMode>(channelModeInt);

   json::Value channelId = obj["channel_id"];
   if (!channelId.is_null())
      pProc->channelId_ = channelId.get_str();

   pProc->altBufferActive_ = obj["alt_buffer"].get_bool();

   json::Value cwdValue = obj["cwd"];
   if (!cwdValue.is_null())
   {
      std::string cwd = cwdValue.get_str();
      if (!cwd.empty())
         pProc->cwd_ = module_context::resolveAliasedPath(obj["cwd"].get_str());
   }

   pProc->cols_ = obj["cols"].get_int();
   pProc->rows_ = obj["rows"].get_int();

   pProc->restarted_ = obj["restarted"].get_bool();
   int autoCloseInt = obj["autoclose"].get_int();
   pProc->autoClose_ = static_cast<AutoCloseMode>(autoCloseInt);
   pProc->zombie_ = obj["zombie"].get_bool();
   pProc->trackEnv_ = obj["track_env"].get_bool();

   return pProc;
}

std::string ConsoleProcessInfo::loadConsoleProcessMetadata()
{
   return console_persist::loadConsoleProcessMetadata();
}

void ConsoleProcessInfo::deleteOrphanedLogs(bool (*validHandle)(const std::string&))
{
   console_persist::deleteOrphanedLogs(validHandle);
}

void ConsoleProcessInfo::saveConsoleProcesses(const std::string& metadata)
{
   console_persist::saveConsoleProcesses(metadata);
}

void ConsoleProcessInfo::saveConsoleEnvironment(const core::system::Options& environment)
{
   console_persist::saveConsoleEnvironment(handle_, environment);
}

void ConsoleProcessInfo::loadConsoleEnvironment(const std::string& handle, core::system::Options* pEnv)
{
   console_persist::loadConsoleEnvironment(handle, pEnv);
}

} // namespace console_process_info
} // namespace session
} // namespace rstudio
