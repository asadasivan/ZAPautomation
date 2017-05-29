#!/usr/bin/python
'''
/*
 * @File: ZAP_ActiveScan.py
 * @Author: Arunkumar Sadasivan
 * @Date: Apr 15th 2017
 * @Description: This script is used for CI/CD security testing pipleline. It uses the ZAP proxy history to get 
                 the list of URLs to scan. The proxy history or URLs to scan is populated by Selenium or testNG or 
                 other automated tests. It also sets up form based authentication to perform active scan as user. 
 * @Usage: python ZAP_ActiveScan.py
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
import ZAPCommon
import ZAPFormAuth

############ Default Values ############
# Load configuration
ZAPCommon = ZAPCommon.ZAPCommon()
config = ZAPCommon.config
ZAP_apikey = ZAPCommon.ZAP_apikey
ZAP_baseURL = ZAPCommon.ZAP_baseURL
ZAP_apiformat = ZAPCommon.ZAP_apiformat

# Get proxy history (site-tree) of ZAP and filter duplicates        
def getProxyHistory():
    viewSitesPath = config['ZAP_core']['viewSitesPath']
    #viewSiteURL = ZAP_baseURL + "/" + viewSitesPath
    payload ={'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey}
    site_list = ZAPCommon.initiateZAPAPI(viewSitesPath,'','',payload)
    return site_list.json()
    
#     if site_list:
#         print "[Info] No. of sites to test: " + str(len(site_list))
#         for key in site_list['sites']:
#             print  key
            
#Exclude certain sites from the the scan            
def excludeSitesfromScan():
    excludeFromScanPath = config['ascan']['excludeFromScanPath']
    excludeSites = config['application']['excludeSites']
    for excludeSite in excludeSites:
        payload ={'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'regex':excludeSite}
        #print "[Info] Excluding site: " + excludeSite + "from active scan"
        ZAPCommon.initiateZAPAPI(excludeFromScanPath,'','',payload)
    
    #payload = {'key1': 'value1', 'key2': 'value2'}  

# Sets whether or not the HTTP Headers of all requests should be scanned   
def scanAllRequestHeaders():
    scanAllRequestHeadersPath = config['ascan']['scanAllRequestHeadersPath']
    scanRequestHeader = config['application']['scanRequestHeader']
    payload ={'zapapiformat':ZAP_apiformat,'apikey':ZAP_apikey,'Boolean':scanRequestHeader}
        #print "[Info] Excluding site: " + excludeSite + "from active scan"
    ZAPCommon.initiateZAPAPI(scanAllRequestHeadersPath,'','',payload)
                  
 
# Initiate active scan        
def runActiveScan(contextId,scanPolicyName):
    domain = config['ascan']['domain']
    activescanPath = config['ascan']['activescanPath']
    excludeSitesfromScan()
    scanAllRequestHeaders() # check if Request headers needs to be scanned
    site_list = getProxyHistory() # get list of URLs to scan
    if site_list:
        print "[Info] No. of sites to test: " + str(len(site_list))
        for URL in site_list['sites']:
            print  "[Info] Running active scan for URL: " + URL
            if getDomainName(URL) in domain: # ignore domains
                continue
            if scanPolicyName == None:
                payload = {'zapapiformat':ZAP_apiformat, 'apikey':ZAP_apikey, 'url':URL, 'recurse':True, 
                           'inScopeOnly':False, 'contextId':contextId
                }
            else:
                payload = {'zapapiformat':ZAP_apiformat, 'apikey':ZAP_apikey, 'url':URL, 'recurse':True, 
                           'inScopeOnly':False, 'scanPolicyName':scanPolicyName,'contextId':contextId
                }
             
            ascan_response = ZAPCommon.initiateZAPAPI(activescanPath,'','',payload)
            scanID = ascan_response.json()['scan']
            scan_status = -1
            while (int(scan_status) < 100):
                time.sleep(10) # 10 seconds
                scan_status = getScanStatus(scanID).json()['status']
                print "[Info] Active Scan in progress. " + scan_status + "% completed. " + "Please wait...."
            print "[Done] Active Scan completed" 


# Initiate active scan by logging in as user       
def runActiveScanAsUser(contextId,scanPolicyName,userId):
    domain = config['application']['excludeDomain']
    activescanPath = config['ascan']['scanAsUser']
    excludeSitesfromScan()
    scanAllRequestHeaders() # check if Request headers needs to be scanned
    site_list = getProxyHistory() # get list of sites to scan
    if site_list:
        print "[Info] No. of sites to test: " + str(len(site_list))
        for URL in site_list['sites']:
            print  "[Info] Running active scan for URL: " + URL
            if getDomainName(URL) in domain: # ignore domains
                continue
            if scanPolicyName == None:
                payload = {'zapapiformat':ZAP_apiformat, 'apikey':ZAP_apikey, 'url':URL, 'recurse':True, 
                           'inScopeOnly':False, 'contextId':contextId }
            else:
                payload = {'zapapiformat':ZAP_apiformat, 'apikey':ZAP_apikey, 'url':URL, 'recurse':True, 
                           'inScopeOnly':False, 'scanPolicyName':scanPolicyName,'contextId':contextId, 'userId':userId }
             
            ascan_response = ZAPCommon.initiateZAPAPI(activescanPath,'','',payload)
            print ascan_response.json()
            scanID = ascan_response.json()['scanAsUser']
            scan_status = -1
            while (int(scan_status) < 100):
                time.sleep(10) # 10 seconds
                scan_status = getScanStatus(scanID).json()['status']
                print "[Info] Active Scan in progress. " + scan_status + "% completed. " + "Please wait...."
            print "[Done] Active Scan completed"      
    
def getDomainName(URL):
    domainName = urlparse(URL).hostname.split('.')[1]   
    return domainName

# Scan status
def getScanStatus(scanID):
    statusPath = config['ascan']['scanstatusPath'] 
    #StatusURL = ZAP_baseURL + "/" + statusPath
    payload = {'zapapiformat':ZAP_apiformat,'scanId':scanID}
    status_response = ZAPCommon.initiateZAPAPI(statusPath,'','',payload)
    return status_response 

    
def printActiveScanResults():
    #response = getScanAlerts('https://workbench-c2-staging.bazaarvoice.com')
    response = ZAPCommon.getScanAlerts()
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

contextName = config['context']['name']

contextId = 4
URL = config['application']['applicationURL']
userName = config['application']['userName']  
userId = 3
customScan = config['application']['customScanPolicy']
if customScan:   # use custom scan policy or tests
    scanPolicyName = config['ascan']['scanPolicyName']
    enableScanners_resp = ZAPCommon.createCustomScanTest(scanPolicyName)
    if enableScanners_resp.status_code == 200:
        print "[Done] Custom Scan Policy Successfully created. "
        runActiveScanAsUser(contextId,scanPolicyName,userId)
        #applicationURL = 'https://workbench-c2-staging.bazaarvoice.com'
        #applicationURL = 'https://s3.amazonaws.com/bvjs-apps'
    else: # Run all tests
        runActiveScanAsUser(contextId,None)
printActiveScanResults() 
        

