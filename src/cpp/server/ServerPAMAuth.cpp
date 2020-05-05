/*
 * ServerPAMAuth.cpp
 *
 * Copyright (C) 2009-16 by RStudio, Inc.
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
#include "ServerPAMAuth.hpp"

#include <core/Error.hpp>
#include <core/PeriodicCommand.hpp>
#include <core/Thread.hpp>
#include <core/system/Process.hpp>
#include <core/FileSerializer.hpp>
#include <core/system/Crypto.hpp>
#include <core/system/PosixSystem.hpp>
#include <core/system/PosixUser.hpp>
#include <core/system/PosixGroup.hpp>
#include <core/json/JsonRpc.hpp>

#include <core/http/Request.hpp>
#include <core/http/Response.hpp>
#include <core/http/URL.hpp>
#include <core/http/AsyncUriHandler.hpp>
#include <core/text/TemplateFilter.hpp>

#include <monitor/MonitorClient.hpp>

#include <server/auth/ServerCSRFToken.hpp>
#include <server/auth/ServerValidateUser.hpp>
#include <server/auth/ServerSecureUriHandler.hpp>
#include <server/auth/ServerAuthHandler.hpp>
#include <server/auth/ServerSecureCookie.hpp>

#include <server/ServerOptions.hpp>
#include <server/ServerUriHandlers.hpp>
#include <server/ServerSessionProxy.hpp>
#include <server/ServerCryptVerifier.hpp>

namespace rstudio {
namespace server {
namespace pam_auth {

bool canSetSignInCookies();
bool canStaySignedIn();
void onUserAuthenticated(const std::string& username,
                         const std::string& password);
void onUserUnauthenticated(const std::string& username);

namespace {

void assumeRootPriv()
{
    // RedHat 5 returns PAM_SYSTEM_ERR from pam_authenticate if we're
    // running with geteuid != getuid (as is the case when we temporarily
    // drop privileges). We've also seen kerberos on Ubuntu require
    // priv to work correctly -- so, restore privilliges in the child
    if (core::system::realUserIsRoot())
    {
       Error error = core::system::restorePriv();
       if (error)
       {
          LOG_ERROR(error);
          // intentionally fail forward (see note above)
       }
    }
}

const char * const kUserId = "user-id";
const char * const kUid = "uid";
const char * const kUserName = "userName";
const char * const kUserGroup = "userGroup";
const char * const kUserHomeDir = "homeDir";
const char * const ENV_DEF_HOME_DIR = "def-home-dir";

// It's important that URIs be in the root directory, so the cookie
// gets set/unset at the correct scope!
const char * const kDoSignIn = "/auth-do-sign-in";
const char * const kPublicKey = "/auth-public-key";

const char * const kAppUri = "appUri";

const char * const kErrorParam = "error";
const char * const kErrorDisplay = "errorDisplay";
const char * const kErrorMessage = "errorMessage";

const char * const kFormAction = "formAction";

const char * const kStaySignedInDisplay = "staySignedInDisplay";

const char * const kLoginPageHtml = "loginPageHtml";

enum ErrorType 
{
   kErrorNone,
   kErrorInvalidLogin,
   kErrorServer 
};
int stoi(const std::string& s) {
    std::istringstream str(s);
    int i;
    str >> i;
    return i;
}

// this method converts the alpha-numeric ids 
// to all-numeric uid
std::string getUniqueNumberAsStringFromUserId(std::string uid){

    boost::regex re("[0-9]+");
    //check if the uid recieved is all-numeric
    // return without processing futhur in that case
    if(boost::regex_match(uid, re))
        return uid;
    //now that the string is alpha-numeric
    //convert it into lower-case characters
    transform(uid.begin(), uid.end(), uid.begin(), ::tolower);
    int n = uid.length();
    char char_array[n+1];
    //build a char array from the string
    strcpy(char_array, uid.c_str());
    std::string final_str;
    long curr_dig;
    for (int i=0; i<n; i++){
        curr_dig = char_array[i];
        //for nummeric characters just append 
        //as-it-is to the final_string
        if(isdigit(curr_dig)){
            std::string a;
            a = char_array[i];
            final_str +=a;
        }else{
            // for non-numeric characters find the 
            // digit at ones place of the ascii value
            // append that to the final_string
            int x = curr_dig % 10;
            final_str +=boost::to_string(x);
        }
    }
    return final_str;
}

std::string errorMessage(ErrorType error)
{
   switch (error)
   {
      case kErrorNone:
         return "";
      case kErrorInvalidLogin: 
         return "Incorrect or invalid username/password";
      case kErrorServer:
         return "Temporary server error, please try again";
   }
   return "";
}

std::string applicationURL(const http::Request& request,
                           const std::string& path = std::string())
{
   return http::URL::uncomplete(
         request.uri(),
         path);
}

std::string applicationSignInURL(const http::Request& request,
                                 const std::string& appUri,
                                 ErrorType error = kErrorNone)
{
   // build fields
   http::Fields fields ;
   if (appUri != "/")
      fields.push_back(std::make_pair(kAppUri, appUri));
   if (error != kErrorNone)
     fields.push_back(std::make_pair(kErrorParam, 
                                     safe_convert::numberToString(error)));

   // build query string
   std::string queryString ;
   if (!fields.empty())
     http::util::buildQueryString(fields, &queryString);

   // generate url
   std::string signInURL = applicationURL(request, auth::handler::kSignIn);
   if (!queryString.empty())
     signInURL += ("?" + queryString);
   return signInURL;
}

std::string getUserIdentifier(const core::http::Request& request)
{
   if (server::options().authNone())
      return core::system::username();
   else
      return auth::secure_cookie::readSecureCookie(request, kUserId);
}

std::string userIdentifierToLocalUsername(const std::string& userIdentifier)
{
   static core::thread::ThreadsafeMap<std::string, std::string> cache;
   std::string username = userIdentifier;

   if (cache.contains(userIdentifier)) 
   {
      username = cache.get(userIdentifier);
   }
   else
   {
      // The username returned from this function is eventually used to create
      // a local stream path, so it's important that it agree with the system
      // view of the username (as that's what the session uses to form the
      // stream path), which is why we do a username => username transform
      // here. See case 5413 for details.
      core::system::user::User user;
      Error error = core::system::user::userFromUsername(userIdentifier, &user);
      if (error) 
      {
         // log the error and return the PAM user identifier as a fallback
         LOG_ERROR(error);
	 
      }
      else
      {
         username = user.username;
      }

      // cache the username -- we do this even if the lookup fails since
      // otherwise we're likely to keep hitting (and logging) the error on
      // every request
      cache.set(userIdentifier, username);
   }

   return username;
}
bool addUserToLocal(std::string encodeUserInfo , std::string & xUserName)	{

   if(encodeUserInfo.empty())	{
	return true;	
   }

   
   Error error;	
   std::vector<unsigned char> decodedData;
   error = core::system::crypto::base64Decode(encodeUserInfo,&decodedData);
   if(error)	{
	LOG_ERROR(error);
     return false;
   }
   std::string userInfo(decodedData.begin(),decodedData.end());	

   json::Value userVal;

   // parse event value object from the request
   if (!json::parse(userInfo, &userVal) ||
       userVal.type() != json::ObjectType)
      return Error(json::errc::ParseError, ERROR_LOCATION);

   // read the event from the object

   	std::string userName = "";
   	std::string homeDir = "";
   	std::string suserId = "";
   	std::string sgroupId = "";

      // extract the fields
      json::Object& requestObject = userVal.get_obj();
      for (json::Object::const_iterator it = 
            requestObject.begin(); it != requestObject.end(); ++it)
      {
         std::string fieldName = it->first ;
         json::Value fieldValue = it->second ;

         if ( fieldName == kUserName )
         {
            if (fieldValue.type() != json::StringType)
               return Error(json::errc::InvalidRequest, ERROR_LOCATION) ;

            userName = fieldValue.get_str() ;
	    xUserName.assign(userName);
         } 
	 else if(fieldName == kUserHomeDir)
	 {
            if (fieldValue.type() != json::StringType)
               return Error(json::errc::InvalidRequest, ERROR_LOCATION) ;

            homeDir = fieldValue.get_str() ;
	 }
	 else if(fieldName == kUid)
	 {
            if (fieldValue.type() != json::StringType)
               return Error(json::errc::InvalidRequest, ERROR_LOCATION) ;

            suserId = fieldValue.get_str() ;
	 }
	 else if(fieldName == kUserGroup)
	 {
            if (fieldValue.type() != json::StringType)
               return Error(json::errc::InvalidRequest, ERROR_LOCATION) ;

            sgroupId = fieldValue.get_str() ;
	 }

     }

   if(userName.empty() || suserId.empty())	{
	LOG_ERROR_MESSAGE("User name and id cannot be empty");		
	return false;
   }
   if(sgroupId.empty()){
	LOG_ERROR_MESSAGE("group Id cannot be empty");		
	return false;
   }
   if(homeDir.empty())	{
	LOG_ERROR_MESSAGE("WARN:: Home directory is empty . Defaulting the user under base directory /var/lib/dsp/dspvolume/\n");		
	const char * defBaseHome= getenv(ENV_DEF_HOME_DIR);
	if( defBaseHome == NULL || defBaseHome[0] == '\0' )	{
		defBaseHome = "/var/lib/dsp/dspvolume/";
	}
	homeDir =defBaseHome+userName;
	//return false;
   }

	LOG_ERROR_MESSAGE("aAdding users ...."+ homeDir);
   int userId = stoi(getUniqueNumberAsStringFromUserId(suserId));
   int groupId= stoi(sgroupId);
   core::system::user::User user;

   if (error){
	LOG_ERROR(error);
     return false;
   }

   core::system::group::Group group;
   error = core::system::group::groupFromId(groupId, &group);
   if(error)	{
	
	// assumes group does not exists
       core::system::group::Group group; 
       group.groupId=groupId;
       group.name="dspusrsgrp"+ sgroupId;
       error = core::system::group::addGroup(&group);

       if(error)	{
	 LOG_ERROR(error);
  	 return false;
       }

   }
   error = core::system::user::userFromUsername(userName,&user);
   if (error) 
   {
      user.userId=userId;
      user.username=userName;
      user.groupId=groupId;
      user.homeDirectory=homeDir;
      error = core::system::user::addUser(&user);
	
      if(error)	{
	 LOG_ERROR(error);
          return  false;	
      } 
	 
   }
   return true;
}


bool mainPageFilter(const http::Request& request,
                    http::Response* pResponse)
{
   // check for user identity, if we have one then allow the request to proceed
   std::string userIdentifier = getUserIdentifier(request);
   if (userIdentifier.empty())
   {
      // otherwise redirect to sign-in
      pResponse->setMovedTemporarily(request, applicationSignInURL(request, request.uri()));
      return false;
   }
   else
   {
      return true;
   }
}

void signInThenContinue(const core::http::Request& request,
                        core::http::Response* pResponse)
{
   pResponse->setMovedTemporarily(request, applicationSignInURL(request, request.uri()));
}

void refreshCredentialsThenContinue(
            boost::shared_ptr<core::http::AsyncConnection> pConnection)
{
   // no silent refresh possible so delegate to sign-in and continue
   signInThenContinue(pConnection->request(),
                      &(pConnection->response()));

   // write response
   pConnection->writeResponse();
}

void signIn(const http::Request& request,
            http::Response* pResponse)
{
   auth::secure_cookie::remove(request,
                               kUserId,
                               "/",
                               pResponse);

   std::map<std::string,std::string> variables;
   variables["action"] = applicationURL(request, kDoSignIn);
   variables["publicKeyUrl"] = applicationURL(request, kPublicKey);

   // setup template variables
   std::string error = request.queryParamValue(kErrorParam);
   variables[kErrorMessage] = errorMessage(static_cast<ErrorType>(
            safe_convert::stringTo<unsigned>(error, kErrorNone)));
   variables[kErrorDisplay] = error.empty() ? "none" : "block";
   variables[kStaySignedInDisplay] = canStaySignedIn() ? "block" : "none";
   if (server::options().authEncryptPassword())
      variables[kFormAction] = "action=\"javascript:void\" "
                               "onsubmit=\"submitRealForm();return false\"";
   else
      variables[kFormAction] = "action=\"" + variables["action"] + "\"";

   variables[kAppUri] = request.queryParamValue(kAppUri);

   // include custom login page html
   variables[kLoginPageHtml] = server::options().authLoginPageHtml();

   // get the path to the JS file
   Options& options = server::options();
   FilePath wwwPath(options.wwwLocalPath());
   FilePath signInPath = wwwPath.complete("templates/encrypted-sign-in.htm");

   text::TemplateFilter filter(variables);

   // don't allow sign-in page to be framed by other domains (clickjacking
   // defense)
   pResponse->setFrameOptionHeaders(options.wwwFrameOrigin());

   pResponse->setFile(signInPath, request, filter);
   pResponse->setContentType("text/html");
}

void publicKey(const http::Request&,
               http::Response* pResponse)
{
   std::string exp, mod;
   core::system::crypto::rsaPublicKey(&exp, &mod);
   pResponse->setNoCacheHeaders();
   pResponse->setBody(exp + ":" + mod);
   pResponse->setContentType("text/plain");
}

void setSignInCookies(const core::http::Request& request,
                      const std::string& username,
                      bool persist,
                      core::http::Response* pResponse)
{
   int staySignedInDays = server::options().authStaySignedInDays();
   boost::optional<boost::gregorian::days> expiry;
   if (persist && canStaySignedIn())
      expiry = boost::gregorian::days(staySignedInDays);
   else
      expiry = boost::none;

   auth::secure_cookie::set(kUserId,
                            username,
                            request,
                            boost::posix_time::time_duration(24*staySignedInDays,
                                                             0,
                                                             0,
                                                             0),
                            expiry,
                            "/",
                            pResponse);

   // add cross site request forgery detection cookie
   auth::csrf::setCSRFTokenCookie(request, pResponse);
}

void doSignIn(const http::Request& request,
              http::Response* pResponse)
{
   std::string appUri = request.formFieldValue(kAppUri);
   std::cout <<" Inside do sign in";
   if (appUri.empty())
      appUri = "/";



   bool persist = false;
   std::string username, password,secretKey,randomId,signedDate,signature,userInfo;


   if (server::options().authEncryptPassword())
   {
      	persist = request.formFieldValue("persist") == "1";
      	FilePath wwwPath(server::options().wwwLocalPath());
      	FilePath secretKeyPath = wwwPath.complete("templates/secretKey.txt");
      	std::string content;
      	Error error1 = core::readStringFromFile(secretKeyPath, &content);
      	if(error1){
            LOG_ERROR(error1);
      	    pResponse->setMovedTemporarily(
               request,
               applicationSignInURL(request,
                                    appUri,
                                    kErrorServer));
         	return;
      	}	
      
      	std::string headers;
   	for(http::Headers::const_iterator it = request.headers().begin();it != request.headers().end();++it)
   	{
      		if(it->name=="x-user"){
         		username=it->value;
      		}	
      		if(it->name=="secretkey"){
         		secretKey=it->value;
      		}	
  	} 

 
      if(secretKey != boost::algorithm::trim_copy(content)){
	 pResponse->setMovedTemporarily(
               request,
               applicationSignInURL(request,
                                   appUri,
                                    kErrorInvalidLogin));
         return;
      }
      //LOG_ERROR_MESSAGE(secretKey);
   }
   else if (server::options().authSignEnabled())	{
      	persist = request.formFieldValue("persist") == "1";
	
      	std::string headers;
   	for(http::Headers::const_iterator it = request.headers().begin();it != request.headers().end();++it)
   	{
      	
		if(it->name==HEADER_KEY_RANDOM)	{
		   randomId=it->value;
		}
		if(it->name==HEADER_KEY_SIGNED_DATE)	{
		   signedDate=it->value;
		}
		if(it->name==HEADER_KEY_SIGNATURE)	{
		   signature=it->value;
		}
		if(it->name==HEADER_KEY_USER_INFO)	{
		  userInfo=it->value;
		}

	}
	std::string signStr = userInfo +":" + randomId + ":" + signedDate;
	std::string base64Str;
	std::vector<unsigned char> data(signStr.begin(), signStr.end());
	Error error = core::system::crypto::base64Encode(data,&base64Str);
	
	// free up of memory of variables
	// free(signData);
	if(error)	{
	
	 LOG_ERROR(error);
	 	pResponse->setMovedTemporarily(
               		request,
               		applicationSignInURL(request,
                                   appUri,
                                    kErrorInvalidLogin));
	// free up of variables memory in case of failure
	 //free(b64message);
         return;

	}
	const char *lPublicCert = getenv(ENV_SIGN_PUB_KEY_FILE);

	int result= verify_sign(lPublicCert,strdup(base64Str.c_str()), strdup(signature.c_str()));
	//free(b64message);
	if(result == EXIT_FAILURE)	{
	 LOG_ERROR_MESSAGE("Failed to verify the signature \n");
	 	pResponse->setMovedTemporarily(
               		request,
               		applicationSignInURL(request,
                                   appUri,
                                    kErrorInvalidLogin));
         return;

	}
	
   }
   else
   {
      persist = request.formFieldValue("staySignedIn") == "1";
      username = request.formFieldValue("username");
      password = request.formFieldValue("password");
   }
   username = "";	
   if(!auth::handler::addUserToLocal(userInfo,username)){

      // register failed login with monitor
      using namespace monitor;
      client().logEvent(Event(kAuthScope,
                              kAuthLoginFailedEvent,
                              "",
                              username));

      pResponse->setMovedTemporarily(
            request,
            applicationSignInURL(request,
                                 appUri,
                                 kErrorInvalidLogin));
	return;
    }

   // tranform to local username
   username = auth::handler::userIdentifierToLocalUsername(username);
   onUserUnauthenticated(username);
   if ( server::auth::validateUser(username))
   {
      if (appUri.size() > 0 && appUri[0] != '/')
         appUri = "/" + appUri;

      setSignInCookies(request, username, persist, pResponse);
      pResponse->setMovedTemporarily(request, appUri);

      // register login with monitor
      using namespace monitor;
      client().logEvent(Event(kAuthScope,
                              kAuthLoginEvent,
                              "",
                              username));

      onUserAuthenticated(username, password);
   }
   else
   {
      // register failed login with monitor
      using namespace monitor;
      client().logEvent(Event(kAuthScope,
                              kAuthLoginFailedEvent,
                              "",
                              username));

      pResponse->setMovedTemporarily(
            request,
            applicationSignInURL(request,
                                 appUri,
                                 kErrorInvalidLogin));
   }
}

void signOut(const http::Request& request,
             http::Response* pResponse)
{
   // validate sign-out request
   if (!auth::csrf::validateCSRFForm(request, pResponse))
      return;

   // register logout with monitor if we have the username
   std::string userIdentifier = getUserIdentifier(request);
   std::string userInfo;
   if (!userIdentifier.empty())
   {
      std::string username = userIdentifierToLocalUsername(userIdentifier);

      using namespace monitor;
      client().logEvent(Event(kAuthScope,
                              kAuthLogoutEvent,
                              "",
                              username));

      onUserUnauthenticated(username);
   }

   auth::secure_cookie::remove(request,
                               kUserId,
                               "/",
                               pResponse);
   pResponse->setMovedTemporarily(
            request,
            applicationSignInURL(request,
                                 auth::handler::kSignIn,
                                 kErrorInvalidLogin));
}

} // anonymous namespace


bool pamLogin(const std::string& username, const std::string& password)
{
   // get path to pam helper
   FilePath pamHelperPath(server::options().authPamHelperPath());
   if (!pamHelperPath.exists())
   {
      LOG_ERROR_MESSAGE("PAM helper binary does not exist at " +
                        pamHelperPath.absolutePath());
      return false;
   }

   // form args
   std::vector<std::string> args;
   args.push_back(username);

   // options (assume priv after fork)
   core::system::ProcessOptions options;
   options.onAfterFork = assumeRootPriv;

   // run pam helper
   core::system::ProcessResult result;
   Error error = core::system::runProgram(pamHelperPath.absolutePath(),
                                          args,
                                          password,
                                          options,
                                          &result);
   if (error)
   {
      LOG_ERROR(error);
      return false;
   }

   // check for success
   return result.exitStatus == 0;
}


Error initialize()
{
   // register ourselves as the auth handler
   server::auth::handler::Handler pamHandler;
   pamHandler.getUserIdentifier = getUserIdentifier;
   pamHandler.userIdentifierToLocalUsername = userIdentifierToLocalUsername;
   pamHandler.addUserToLocal = addUserToLocal;
   pamHandler.mainPageFilter = mainPageFilter;
   pamHandler.signInThenContinue = signInThenContinue;
   pamHandler.refreshCredentialsThenContinue = refreshCredentialsThenContinue;
   pamHandler.signIn = signIn;
   pamHandler.signOut = signOut;
   if (canSetSignInCookies())
      pamHandler.setSignInCookies = setSignInCookies;
   auth::handler::registerHandler(pamHandler);

   // add pam-specific auth handlers
   uri_handlers::addBlocking(kDoSignIn, doSignIn);
   uri_handlers::addBlocking(kPublicKey, publicKey);

   // initialize crypto
   return core::system::crypto::rsaInit();
}


} // namespace pam_auth
} // namespace server
} // namespace rstudio
