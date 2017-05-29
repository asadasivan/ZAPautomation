#!/usr/bin/python

'''
/*
 * @File: ZAP_ActiveScanner.py
 * @Author: Arunkumar Sadasivan
 * @Date: Apr 15th 2017
 * @Description: This script is used for CI/CD security testing pipleline. It uses the ZAP proxy history to get 
                 the list of URLs to scan. The proxy history or URLs to scan is populated by Selenium or testNG or 
                 other automated tests. It also sets up form based authentication to perform active scan as user. 
 * @Usage: python ZAP_scanner.py
 */
'''
import sys
import os
import subprocess
#import re
import requests
#import yaml
import json
from urlparse import urlparse
import time
import urllib

############ Default Values ############
# Load configuration
configFile = 'ZAPconfig.json'
with open(configFile) as json_data_file:
    data = json.load(json_data_file)
# print(data['default']['ZAP_node'])
ZAP_apikey = data['default']['ZAP_apikey']
ZAP_baseURL = data['default']['ZAP_baseURL'] # ip of ZAP node
ZAP_apiformat = data['default']['ZAP_apiformat']



# Common methods to initiate ZAP API request
def initiateZAPAPI(path,username,password,payload):
    # Make HTTP requests
    # to view site history: http://127.0.0.1:8082/UI/core/view/sites/
    URL = ZAP_baseURL + "/" + path
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

# Get proxy history (site-tree) of ZAP and filter duplicates        
def getProxyHistory():
    viewSitesPath = data['ZAP_core']['viewSitesPath']
    #viewSiteURL = ZAP_baseURL + "/" + viewSitesPath
    payload ={'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey}
    site_list = initiateZAPAPI(viewSitesPath,'','',payload)
    return site_list.json()
    
#     if site_list:
#         print "[Info] No. of sites to test: " + str(len(site_list))
#         for key in site_list['sites']:
#             print  key
            
#Exclude certain sites from the the scan            
def excludeScanSitesScan():
    excludeFromScanPath = data['ascan']['excludeFromScanPath']
    excludeSites = data['ascan']['excludeSites']
    for excludeSite in excludeSites:
        payload ={'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'regex':excludeSite}
        #print "[Info] Excluding site: " + excludeSite + "from active scan"
        initiateZAPAPI(excludeFromScanPath,'','',payload)
    
    #payload = {'key1': 'value1', 'key2': 'value2'}            
 
# Initiate active scan        
def runActiveScan(scanPolicyName,contextId):
    domain = data['ascan']['domain']
    activescanPath = data['ascan']['activescanPath']
    excludeScanSitesScan()
    site_list = getProxyHistory() # get list of URLs to scan
    if site_list:
        print "[Info] No. of sites to test: " + str(len(site_list) - 1)
        for URL in site_list['sites']:
            print  "[Info] Running active scan for URL: " + URL
            if getDomainName(URL) in domain: # ignore domains
                continue
            payload = {'zapapiformat':ZAP_apiformat, 'apikey':ZAP_apikey, 'url':URL, 'recurse':True, 
                       'inScopeOnly':False, 'scanPolicyName':scanPolicyName,'contextId':contextId
            }
            
            ascan_response = initiateZAPAPI(activescanPath,'','',payload)
            scanID = ascan_response.json()['scan']
            scan_status = -1
            while (scan_status < 100):
                time.sleep(10) # 10 seconds
                scan_status = getScanStatus(scanID).json()['status']
                # print ('active scan progress %: scan_status)
                print scan_status
                print "[Info] Scan in progress. Please wait...."
            print "[Done] Active Scan completed"    
    
def getDomainName(URL):
    domainName = urlparse(URL).hostname.split('.')[1]   
    return domainName

# Scan status
def getScanStatus(scanID):
    statusPath = data['ascan']['scanstatusPath'] 
    #StatusURL = ZAP_baseURL + "/" + statusPath
    payload = {'zapapiformat':ZAP_apiformat,'scanId':scanID}
    status_response = initiateZAPAPI(statusPath,'','',payload)
    return status_response 

# Get Scan Results
# def getScanAlerts(applicationURL):
#     viewAlertsPath = data['ZAP_core']['viewAlertsPath']
#     viewAlertsURL = ZAP_baseURL + "/" + viewAlertsPath
#     payload = {'zapapiformat':ZAP_apiformat,'baseurl':applicationURL}
#     alerts_response = initiateZAPAPI(viewAlertsURL,'','',payload)
#     return alerts_response

def getScanAlerts():
    viewAlertsPath = data['ZAP_core']['viewAlertsPath']
    #payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'baseurl':applicationURL}
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey}
    alerts_response = initiateZAPAPI(viewAlertsPath,'','',payload)
    return alerts_response


# context is required to add alert filter (false positives)
def createContext(contextName): 
    #removeContext(contextName) # clean old context or configuration
    createContextPath = data['context']['createContextPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'contextName':contextName}
    createContext_response = initiateZAPAPI(createContextPath,'','',payload)
    #print context_response.json()['contextId']
    return createContext_response

# Remove existing context
'''
Looks like there is a bug in ZAP. The context list view method returns a string instead of List.
'''
 
def removeContext(contextName): 
    contextListPath = data['context']['contextListPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey}
    contextList_response = initiateZAPAPI(contextListPath,'','',payload) # get context list
    contextList = contextList_response.json()['contextList']
    
    for context in contextList:
        if context == contextName: # if exists delete
            removeContextPath = data['context']['removeContextPath']
            payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'contextName':contextName}
            removeContext_response = initiateZAPAPI(removeContextPath,'','',payload)
            #print context_response.json()['contextId']
            return removeContext_response
            


# Alert filter requires target applications to be in the context of ZAP
# include all URLs in history to Context
def includeURLContext(contextId):
#     contextName = data['context']['name']
#     create_response = createContext(contextName)
#     contextId = create_response.json()['contextId']
    if contextId:
        includePath = data['context']['includeContextPath']
        #hostRegex = ".*"
        hostRegex = "\Qhttps://workbench-c2-staging.bazaarvoice.com\E.*"
        payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'contextName':contextName,'regex':hostRegex}
        include_response = initiateZAPAPI(includePath,'','',payload)
        return include_response
    else:
        print "[Error] Error occurred while trying to create context."

# add alert filter to ZAP    
def setFalsePositives(contextId, ruleId, alertURL, URLisRegex, alertParam):  
    addFilterPath = data['alertFilter']['addAlertFilterPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'contextId':contextId,'ruleId':ruleId,'newLevel':'-1',
                                        'URL':alertURL,'urlIsRegex':URLisRegex,'parameter':alertParam}
    alertFilter_response = initiateZAPAPI(addFilterPath,'','',payload)
    return alertFilter_response

# Clean up scan and logs and create new session
def createNewSession():
    print "[Info] Creating new sessions and clearing previous session data"
    sessionPath = data['ZAP_core']['newSessionPath']
    sessionName = data['ZAP_core']['sessionName']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'name':sessionName,'overwrite':True}
    newSession_response = initiateZAPAPI(sessionPath,'','',payload)
    return newSession_response


# Get scan policy id
def getScanPolicyID(name):
    viewScannersPath = data['ascan']['viewScannersPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey}
    scanPolicy_response = initiateZAPAPI(viewScannersPath,'','',payload)
    scanners = scanPolicy_response.json()['scanners']
     
    for scanner in scanners:
        scanID = scanner['id']
        scanName = scanner['name']
        #print scanID + "," + scanName
        if scanName == name:
            return scanID

def createScanPolicy(scanPolicyName):
    #scanPolicyName = data['ascan']['scanPolicyName']
    removeScanPolicy(scanPolicyName) # remove existing configuration if it exists
    addScanPolicyPath = data['ascan']['addScanPolicyPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'scanPolicyName':scanPolicyName}
    addScanPolicy_response = initiateZAPAPI(addScanPolicyPath,'','',payload)
    return addScanPolicy_response

def removeScanPolicy(scanPolicyName):
    removeScanPolicyPath = data['ascan']['removeScanPolicyPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'scanPolicyName':scanPolicyName}
    removeScanPolicy_response = initiateZAPAPI(removeScanPolicyPath,'','',payload)
    return removeScanPolicy_response
    

def disableAllScanners(scanPolicyName):
    disableAllScannersPath = data['ascan']['disableAllScannersPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'scanPolicyName':scanPolicyName}
    disableAllScanners_response = initiateZAPAPI(disableAllScannersPath,'','',payload)
    return disableAllScanners_response

def enableScanners(scanPolicyName,testIDs):
    enableScannersPath = data['ascan']['enableScannersPath']
    payload = {'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'scanPolicyName':scanPolicyName,'ids':testIDs}
    enableScanners_resp = initiateZAPAPI(enableScannersPath,'','',payload)
    return enableScanners_resp

def createCustomScanTest(scanPolicyName):
    #scanPolicyName = data['ascan']['scanPolicyName']
    createPolicy_resp = createScanPolicy(scanPolicyName)
    if createPolicy_resp.status_code == 200:
        print "[Done] Scan policy: " + scanPolicyName + " successfully created."
        disableAllScanners_resp = disableAllScanners(scanPolicyName)
        if disableAllScanners_resp.status_code == 200:
            testNames = data['ascan']['testNames']
            scanIDArry = []
            for testname in testNames:
                scanID = getScanPolicyID(testname)
                if scanID:
                    scanIDArry.append(scanID)
            # convert scanIDArry to string with delimiter ,
            testIDs = ','.join(map(str, scanIDArry)) # convert into string   
            enableScanners_resp = enableScanners(scanPolicyName,testIDs)     
            if  enableScanners_resp.status_code == 200:
                print "[Done] Enabling custom tests finished..."
                return enableScanners_resp
            else:              
                print "[Error] Error occurred while trying to enable custom tests"         
            
        else:
            print "[Error] Error occurred while trying to disable all tests"  
    else:
        print "[Error] Error occurred while trying to create a scan test policy"   
    
    
def printActiveScanResults():
    #response = getScanAlerts('https://workbench-c2-staging.bazaarvoice.com')
    response = getScanAlerts()
    alerts = response.json()['alerts']
    index = 0
    for findings in alerts:
        '''
        del findings['description']
         del findings['solution']
         del findings['reference']
         del findings['wascid']
         del findings['other']
         del findings ['cweid']
         #del findings ['evidence']
         del findings ['pluginId']
         del findings ['id']
         del findings ['confidence']  
         '''
        index +=1
        #print "Issue: " + findings['name'] + " Severity: " + findings['risk'] + " URL: " + findings['url'] + " Parameter: " + findings['param']
        print str(index) + ":" +" Issue: " + findings['name']
        print "Severity: " + findings['risk'] 
        print "URL: " + findings['url'] 
        print "Parameter: " + findings['param']
        #print "Description: " + findings['description']
        #print "Solution: " + findings ['solution']
      
        #print alerts   
        '''
        risk => severity level
        name => severity name
        '''
            
    
    
####################### Main #########################################        


# Clean up scan and logs and create new session
'''
Uncomment after testing is done
'''
#newSession_response = createNewSession()
# if newSession_response.status_code != 200:
#     print "[Error] Error occurred while trying to create a session"
    
# Alert filter requires target applications to be in the context of ZAP
# include all URLs in history to Context
contextName = data['context']['name']
create_response = createContext(contextName)
contextId = create_response.json()['contextId']
include_response = includeURLContext(contextId)
if include_response.status_code == 200:
    # Create custom scan policy
    scanPolicyName = data['ascan']['scanPolicyName']
    enableScanners_resp = createCustomScanTest(scanPolicyName)
    if enableScanners_resp.status_code == 200:
        runActiveScan(scanPolicyName,contextId)
        #applicationURL = 'https://workbench-c2-staging.bazaarvoice.com'
        #applicationURL = 'https://s3.amazonaws.com/bvjs-apps'
        printActiveScanResults() 
        

