#!/usr/bin/python

'''
/*
 * @File: ZAPFormAuth.py
 * @Author: Arunkumar Sadasivan
 * @Date: Apr 15th 2017
 * @Description: This class sets form authentication for session handling. Set Log in and log out indicator to 
                 specify if the application is in session. Setting this helps Zap to see if it needs to authenticate.
                 It also creates a new user and enables it to perform authentication.
 * @Usage: N/A
 */
'''

import sys
import requests
import urllib


# ############ Default Values ############
# # Load configuration
# config = ZAPCommon.config
# ZAP_apikey = ZAPCommon.getAPIKey() 
# ZAP_baseURL = ZAPCommon.getBaseURL()
# ZAP_apiformat = ZAPCommon.getApiFormat()

class FormAuth(object):
    
    def __init__(self, ZAPCommon): # Constructor
        self.ZAPCommon = ZAPCommon
        self.config = ZAPCommon.config
        self.ZAP_apikey = ZAPCommon.ZAP_apikey
        self.ZAP_baseURL = ZAPCommon.ZAP_baseURL
        self.ZAP_apiformat = ZAPCommon.ZAP_baseURL
                 
    # This method informs ZAP the URL to be used for login and it also defines the parameter used by the application
    def setAuthentication(self, contextId):
        authMethodPath = self.config['authentication']['setAuthMethodPath']
        authMethodName = self.config['authentication']['authMethodName']
        loginURL = self.config['application']['loginURL'] 
#       userName = data['authentication']['userName']
#       password = data['authentication']['password']
        '''
        ZAP api requires loginURL and login request data to be URL encoded. 
        authMethodConfigParams is where you add other parameters that is required for login. Ex. remember me variable etc.
       '''
        userNameParameter = self.config['application']['userNameParameter']
        passwordParameter = self.config['application']['passwordParameter']
        otherLoginParameters = self.config['application']['otherLoginParameters']
        loginRequestData = userNameParameter + "={%username%}&" + passwordParameter + "={%password%}&" + otherLoginParameters
        #authMethodConfigParams = "loginUrl="+ urllib.quote_plus(loginURL) + "&loginRequestData=" + urllib.quote_plus(loginRequestData)
        authMethodConfigParams = "loginUrl="+ loginURL + "&loginRequestData=" + urllib.quote_plus(loginRequestData)
   
        # authMethodConfigParams should be url encoded
        #authMethodConfigParams_enc = urllib.quote_plus(authMethodConfigParams) 
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'authMethodName':authMethodName,
                 'authMethodConfigParams':authMethodConfigParams
                  }
        setAuthMethod_resp = self.ZAPCommon.initiateZAPAPI(authMethodPath,'','',payload)
        if setAuthMethod_resp.status_code == 200:
            print "[Done] Authentication Method Successfully Created"
    

    # Login indicator is required for ZAP to know if the user is in session.   
    def setLoginIndicator(self,contextId):
        setLoggedInIndicatorPath = self.config['authentication']['setLoggedInIndicatorPath']
        loggedInIndicatorRegex = "\Q" + self.config['application']['loggedInIndicatorRegex'] + "\E"
        #loggedInIndicatorRegex_enc = urllib.quote_plus(loggedInIndicatorRegex)
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'loggedInIndicatorRegex':loggedInIndicatorRegex}
        loginIndicator_resp = self.ZAPCommon.initiateZAPAPI(setLoggedInIndicatorPath,'','',payload)
        print loginIndicator_resp
        if loginIndicator_resp.status_code == 200:
            print "[Done] Login Indicator Successfully set"
    
    # Logout indicator is required for ZAP to know if the user needs to be autehnticated again.   
    def setLogoutIndicator(self,contextId):
        setLoggedOutIndicatorPath = self.config['authentication']['setLoggedOutIndicatorPath']
        loggedOutIndicatorRegex = "\Q" + self.config['application']['loggedOutIndicatorRegex'] + "\E"
        #loggedInIndicatorRegex_enc = urllib.quote_plus(loggedInIndicatorRegex)
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'loggedOutIndicatorRegex':loggedOutIndicatorRegex}
        logoutIndicator_resp = self.ZAPCommon.initiateZAPAPI(setLoggedOutIndicatorPath,'','',payload)
        if logoutIndicator_resp.status_code == 200:
            print "[Done] Logout Indicator Successfully set"    

