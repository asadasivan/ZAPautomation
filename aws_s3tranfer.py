#!/usr/bin/env python
'''
/*
 * @File: aws_s2transfer.py
 * @Author: Arunkumar Sadasivan
 * @Date: 7/3/2017
 * @Description: The script is used to perform S3 transactions like upload, download, generate URL to download, delete file,
                 print file contents, check if file exists, list files in bucket etc.
 * @Usage: python aws_s2transfer.py
 */
'''
import datetime
import getpass
import os
import sys
import argparse
import boto3
import boto3.ec2
import botocore
from boto3.s3.transfer import S3Transfer
from boto3.session import Session
import requests

bucketName = "zapscan"
uploadFilePath = "/home/asadasivan/s3test.txt"
downloadFilePath = "/tmp/myfile.txt"
region = "us-east-1"
accountNumber = "549050352176" # replace with account number
#roleName = "people/asadasivan" # replace with role you want to use
roleName = "SecurityScan-XAccount"
#os.environ['AWS_PROFILE']

# # set temporary security credentials to log into AWS
# def getTemporarySecurityCredentials():
#     # The shared credentials file has a default location of ~/.aws/credentials. 
#     # You can change the location of the shared credentials file by setting the AWS_SHARED_CREDENTIALS_FILE environment variable.
#     session = boto3.Session(profile_name='default')
#     # Retrieving temporary credentials using AWS STS
#     sts_client = session.client('sts')
#     '''    
#      Currently the SDK does not support passing the AWS configuration file as environment variables or as shared configuration 
#      file. Until the SDK implements that functionality we need to hard code the RoleArn.
#     '''   
#     # role_arn="arn:aws:iam::account-of-role-to-assume:role/name-of-role"
#     role_arn = "arn:aws:iam::%s:role/%s" % (accountNumber,roleName)
#     role = sts_client.assume_role(RoleArn=role_arn,RoleSessionName="SecurityScan", DurationSeconds=900)
#     return role # role dict contains temporary credentials
# 
# # get temporary access key 
# def getAccessKey(role):
#     # parse the dict to get the temporary credentials
#     access_key = role['Credentials']['AccessKeyId']
#     return access_key
# 
# # get temporary secret key 
# def getSecretKey(role):
#     # parse the dict to get the temporary credentials
#     secret_key = role['Credentials']['SecretAccessKey']
#     return secret_key
# 
# # get security token
# def getSecurityToken(role):
#     # parse the dict to get the temporary credentials
#     security_token = role['Credentials']['SessionToken']
#     return security_token
    
# Provides the client for accessing the Amazon S3 web service.
def initiateS3Client(access_key, secret_key, security_token, region):
    s3Client = boto3.client('s3',region_name = region)
    return s3Client

# upload files to S3
def uploadFiletoS3(bucketName,bucketKey,uploadFilePath):
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    try:
        # provides high level abstractions for efficient uploads/downloads.
        transfer = S3Transfer(s3Client)
        transfer.upload_file(uploadFilePath, bucketName,bucketKey,extra_args={'ServerSideEncryption': 'AES256'})
        print "[Done]: File successfully uploaded."
    except boto3.exceptions.S3UploadFailedError as e:
        print "[Error] Error occurred while trying to upload file from S3." + e


# download files from S3        
def downloadFilefromS3(bucketName,bucketKey,downloadFilePath): 
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    try:
        transfer = S3Transfer(s3Client)
        # Download s3://bucket/key to /tmp/myfile
        transfer.download_file(bucketName,bucketKey, downloadFilePath) 
        print "[Done]: File successfully downloaded to" + downloadFilePath + "."
    except boto3.exceptions.S3UploadFailedError as e:
        print "[Error] Error occurred while trying to download file from S3." + e  

            
'''
 Generates a signed download URL that will work for 1 hour. Signed download URLs will work for the time period even if 
 the object is private (when the time period is up, the URL will stop working).
'''   
        
def generateSignedDownloadURL(bucketName,bucketKey):
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    try:
        # To generate pre-signed URL for S3 upload replace get_object with put_object
        downloadURL = s3Client.generate_presigned_url('get_object',Params={'Bucket': bucketName, 'Key': bucketKey}
                                                                , ExpiresIn=3600)   
        return downloadURL 
    except Exception as e:
        print(e)
        raise e      

# to print contents of a file           
def printFileContents(bucketName,bucketKey):
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    try:
        response = s3Client.get_object(Bucket=bucketName, Key=bucketKey)
        json_data = response['Body'].read()
        print json_data
    except Exception as e:
        print(e)
        raise e      

# delete a file in s3    
def deleteFile(bucketName,bucketKey):
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    try:
        response = s3Client.delete_object(Bucket=bucketName, Key=bucketKey)
        print "[Done] Key: " + bucketKey + "successfully deleted." 
    except Exception as e:
        print(e)
        raise e  

# check if bucket with key exists    
def checkKeyexistsinBucket(bucketName,bucketKey):
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    response = s3Client.list_objects_v2(
        Bucket=bucketName,
        Prefix=bucketKey, # Prefix parameter filter results by prefix server-side before sending them to client:
    )
    for obj in response.get('Contents', []):
        if obj['Key'] == bucketKey: 
            return True  
        
# list_objects operation of Amazon S3 returns up to 1000 objects. Need to use paginators to display more. 
# Prefix parameter is used to filter the paginated results by prefix server-side before sending them to the client:
def listFilesinBucket(bucketName,bucketKey): 
    role = getTemporarySecurityCredentials()
    # get temporary credentials from role
    access_key = getAccessKey(role)
    secret_key = getSecretKey(role)
    security_token = getSecurityToken(role)
    s3Client = initiateS3Client(access_key, secret_key, security_token, region)
    paginator = s3Client.get_paginator('list_objects_v2')
    operation_parameters = {'Bucket': bucketName,
                            'Prefix': bucketKey }
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        #print(page['Contents'])
        for fileName in page['Contents']:
            print fileName['Key']
    
                 
      
###############################################################################
# Main
###############################################################################

#uploadFiletoS3('zapscan','session/test.txt',uploadFilePath)
#downloadFilefromS3('zapscan','session/test.txt', downloadFilePath)
print generateSignedDownloadURL('zapscan','session/test.txt')    
printFileContents('zapscan','session/test.txt')
#deleteFile('zapscan','session/test.txt')
checkKeyexistsinBucket('zapscan','session/test.txt')
listFilesinBucket('zapscan','session')