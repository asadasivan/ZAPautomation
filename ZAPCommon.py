#!/usr/bin/python

'''
/*
 * @File: ZAPCommon.py
 * @Author: Arunkumar Sadasivan
 * @Date: Apr 15th 2017
 * @Description: This class contains all common methods like initiating the ZAP request, create session, create context and 
                 also create custom scan test policy. 
 * @Usage: N/A
 */
'''

import sys
import requests
import urllib
import json
import os

############ Default Values ############
configFile = 'ZAPconfig.json' # configuration file

class ZAPCommon(object):

    def __init__(self): # Constructor
        self.config = self.LoadConfiguration()
        self.ZAP_apikey = self.config['default']['ZAP_apikey']
        self.ZAP_baseURL = self.config['default']['ZAP_baseURL'] # ip of ZAP node
        self.ZAP_apiformat = self.config['default']['ZAP_apiformat']
        
    def LoadConfiguration(self):
        # Load configuration
        with open(configFile) as json_data_file:
            config = json.load(json_data_file)
            return config 
    
#     def getConfig(self):
#         return self.config
#         
#     def getAPIKey(self):
#         return self.ZAP_apikey
#     
#     def getBaseURL(self): 
#         return self.ZAP_baseURL
#     
#     def getApiFormat(self):
#         return self.ZAP_apiformat   
                
    # Common methods to initiate ZAP API request
    def initiateZAPAPI(self, path, username, password, payload):
        # Make HTTP requests
        # to view site history: http://127.0.0.1:8082/UI/core/view/sites/
        URL = self.ZAP_baseURL + "/" + path
        custom_headers = {'Accept': 'application/json'}
        try:
            response = requests.get(URL,auth=(username, password),headers=custom_headers,params=payload)
            if response.status_code == 200:
                #print "Connection success"
                return response
            else:
                response.raise_for_status()        
        except (requests.exceptions.HTTPError,requests.exceptions.ConnectTimeout,requests.exceptions.ConnectionError) as e:
            print e
            sys.exit(1)
            
    # Clean up scan and logs and create new session
    def createNewSession(self):
        print "[Info] Creating new sessions and clearing previous session data"
        sessionPath = self.config['ZAP_core']['newSessionPath']
        sessionName = self.config['ZAP_core']['sessionName']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'name':sessionName,'overwrite':True}
        newSession_response = self.initiateZAPAPI(sessionPath,'','',payload)
        if newSession_response.status_code != 200:
            print "[Error] Error occurred while trying to create a session" 
            
############## Context  #######################################################################                   
        
    # context is required to add alert filter (false positives)
    def createContext(self,contextName): 
        #removeContext(contextName) # clean old context or configuration
        createContextPath = self.config['context']['createContextPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextName':contextName}
        createContext_response = self.initiateZAPAPI(createContextPath,'','',payload)
        #print context_response.json()['contextId']
        return createContext_response

    # Remove existing context
    '''
    Looks like there is a bug in ZAP. The context list view method returns a string instead of List.
    '''
 
    def removeContext(self, contextName): 
        contextListPath = self.config['context']['contextListPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey}
        contextList_response = self.initiateZAPAPI(contextListPath,'','',payload) # get context list
        contextList = contextList_response.json()['contextList']
    
        for context in contextList:
            if context == contextName: # if exists delete
                removeContextPath = self.config['context']['removeContextPath']
                payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextName':contextName}
                removeContext_response = self.initiateZAPAPI(removeContextPath,'','',payload)
                #print context_response.json()['contextId']
                return removeContext_response
            

    # Alert filter requires target applications to be in the context of ZAP
    # include all URLs in history to Context
    def includeURLContext(self, contextName, URL):
        #hostRegex = "\Q" + URL + "\E.*"
        hostRegex = URL+".*"
        includePath = self.config['context']['includeContextPath']
        #hostRegex = ".*"
        # hostRegex = "\Q" + urllib.quote_plus("https://workbench-c2-staging.bazaarvoice.com") + "\E.*"
        #encoded_hostRegex = urllib.quote_plus(hostRegex)
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextName':contextName,'regex':hostRegex}
        include_response = self.initiateZAPAPI(includePath,'','',payload)
        return include_response 

############################################################################################################## 
     
############## Custom Scan test Policy ####################################################################### 

    # Get scan policy id
    def getScanPolicyID(self,name):
        viewScannersPath = self.config['ascan']['viewScannersPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey}
        scanPolicy_response = self.initiateZAPAPI(viewScannersPath,'','',payload)
        scanners = scanPolicy_response.json()['scanners']
        for scanner in scanners:
            scanID = scanner['id']
            scanName = scanner['name']
            #print scanID + "," + scanName
            if scanName == name:
                return scanID

    def createScanPolicy(self,scanPolicyName):
        #scanPolicyName = data['ascan']['scanPolicyName']
        if scanPolicyName in self.getScanPolicies()['scanPolicyNames']:
            self.removeScanPolicy(scanPolicyName) # remove existing configuration if it exists
        addScanPolicyPath = self.config['ascan']['addScanPolicyPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'scanPolicyName':scanPolicyName}
        addScanPolicy_response = self.initiateZAPAPI(addScanPolicyPath,'','',payload)
        return addScanPolicy_response

    def removeScanPolicy(self,scanPolicyName):
        removeScanPolicyPath = self.config['ascan']['removeScanPolicyPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'scanPolicyName':scanPolicyName}
        removeScanPolicy_response = self.initiateZAPAPI(removeScanPolicyPath,'','',payload)
        return removeScanPolicy_response
    

    def disableAllScanners(self,scanPolicyName):
        disableAllScannersPath = self.config['ascan']['disableAllScannersPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'scanPolicyName':scanPolicyName}
        disableAllScanners_response = self.initiateZAPAPI(disableAllScannersPath,'','',payload)
        return disableAllScanners_response

    def enableScanners(self,scanPolicyName,testIDs):
        enableScannersPath = self.config['ascan']['enableScannersPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'scanPolicyName':scanPolicyName,'ids':testIDs}
        enableScanners_resp = self.initiateZAPAPI(enableScannersPath,'','',payload)
        return enableScanners_resp   

    def getScanPolicies(self):
        getScanPoliciesPath=self.config['ascan']['viewScanPoliciesPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey}
        getPolicies_response = self.initiateZAPAPI(getScanPoliciesPath,'','',payload)
        return getPolicies_response

    # Create custom scan or test policy
    def createCustomScanTest(self,scanPolicyName):
        #scanPolicyName = data['ascan']['scanPolicyName']
        createPolicy_resp = self.createScanPolicy(scanPolicyName)
        if createPolicy_resp.status_code == 200:
            print "[Done] Scan policy: " + scanPolicyName + " successfully created."
            disableAllScanners_resp = self.disableAllScanners(scanPolicyName)
            if disableAllScanners_resp.status_code == 200:
                testNames = self.config['ascan']['testNames']
                scanIDArry = []
                for testname in testNames:
                    scanID = self.getScanPolicyID(testname)
                    if scanID:
                        scanIDArry.append(scanID)
                # convert scanIDArry to string with delimiter ,
                testIDs = ','.join(map(str, scanIDArry)) # convert into string   
                enableScanners_resp = self.enableScanners(scanPolicyName,testIDs)     
                if  enableScanners_resp.status_code == 200:
                    print "[Done] Enabling custom tests finished..."
                    return enableScanners_resp
                else:              
                    print "[Error] Error occurred while trying to enable custom tests"         
            else:
                print "[Error] Error occurred while trying to disable all tests"  
        else:
            print "[Error] Error occurred while trying to create a scan test policy"   
            
            
    # add alert filter to ZAP    
    def setFalsePositives(self,contextId, ruleId, alertURL, URLisRegex, alertParam): 
        addFilterPath = self.config['alertFilter']['addAlertFilterPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'ruleId':ruleId,'newLevel':'-1',
                                        'URL':alertURL,'urlIsRegex':URLisRegex,'parameter':alertParam}
        alertFilter_response = self.initiateZAPAPI(addFilterPath,'','',payload)
        return alertFilter_response        
    
##############################################################################################################

 
############## Scan methods ############################################################################
     
    # get Scan results
    def getScanAlerts(self):
        viewAlertsPath = self.config['ZAP_core']['viewAlertsPath']
        #payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'baseurl':applicationURL}
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey}
        alerts_response = self.initiateZAPAPI(viewAlertsPath,'','',payload)
        return alerts_response 
    
    # get scan results filter by URL
    def getScanAlertsURL(self,applicationURL):
        viewAlertsPath = self.config['ZAP_core']['viewAlertsPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'baseurl':applicationURL}
        alerts_response = self.initiateZAPAPI(viewAlertsPath,'','',payload)
        return alerts_response

   
##############################################################################################################

############## Setup User methods #######################################################################
    
    # Create s user
    def createNewUser(self,contextId,userName):
        # Create new user  
        newUserPath = self.config['users']['newUserPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'name':userName}
        createUser_resp = self.initiateZAPAPI(newUserPath,'','',payload)
        if createUser_resp.status_code == 200:
            print "[Done] User: " + userName + "Successfully Created"
            return createUser_resp
    
    # Add credentials (username/password) to the newly created user
    def setAuthCredentialUser(self, userId, userName, contextId): 
        # Add user credentials
        setAuthCredsPath = self.config['users']['setAuthCredsPath']
        #userId = createUser_resp.json()['userId']
        #print "userID: " + userId
        password = self.config['application']['password']
        #authCredCfgParam_enc = urllib.quote_plus("username=") + userName + urllib.quote_plus("&password=") + password
        #print authCredCfgParam_enc
        authCredCfgParam = "username=" + userName + "&password=" + password
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'userId':userId,'authCredentialsConfigParams':authCredCfgParam}
        setAuthCreds_resp = self.initiateZAPAPI(setAuthCredsPath,'','',payload)
        if setAuthCreds_resp.status_code == 200:
            print "[Done] User credentials successfully added."
    
    # Enable the new user
    def enableUser(self, contextId, userId, userName):
        # Enable user
        enableUserPath = self.config['users']['setUserEnabledPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'contextId':contextId,'userId':userId,'enabled':True}
        enableUser_resp = self.initiateZAPAPI(enableUserPath,'','',payload)
        if enableUser_resp.status_code == 200:
            print "[Done] User: " + userName + " successfully enabled."

    def getIDs(self,names):
        ids = ""
        for name in names:
            ids = ids + self.getScanPolicyID(name) + ","
        return ids

    def loadSession(self):
        sessionFile = self.config['application']['sessionFile']
        zapDirectory = self.config['ZAP_info']['ZAP_directory']
        os.system('mv ~/%s %s/zap/session/%s'%(sessionFile, zapDirectory, sessionFile))
        loadSessionPath = self.config['ZAP_core']['loadSessionPath']
        payload = {'zapapiformat':self.ZAP_apiformat,'apikey':self.ZAP_apikey,'name':sessionFile}
        loadSession_resp = self.initiateZAPAPI(loadSessionPath,'','',payload)
        if loadSession_resp.status_code == 200:
            print "[Done] Session successfully loaded"


    
##############################################################################################################

############## ZAP setup methods #######################################################################   

# def startZAP():
#     print "[Info] Staring ZAP ..."
#     subprocess.Popen(['zaproxy/zap.sh','-daemon'],stdout=open(os.devnull,'w'))
#     print 'Waiting for ZAP to load, 10 seconds ...'
#     time.sleep(10)
#     # ToDo
# 
# def stopZAP(zap):
#     print "[Info] Stopping ZAP ..."
#     zap.core.shutdown() 

##############################################################################################################
