#!/usr/bin/python
# -*- coding: utf-8 -*-
###
# (C) Copyright (2012-2019) Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Author : Karthik VR
###

import requests
import json
import time 
from time import sleep
from dateutil import parser as dateParser
import os
import sys
import argparse
from datetime import datetime

import base64

# Suppress warning - InsecureRequestWarning: Unverified HTTPS request is being made
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# logging object is obtained from main (caller module)
global logging

# Flag to indicate whether to write full alert payload or custom messages : 0 - Full logging, 1 - Custom logging
global fullOrCustomlogFlag 
fullOrCustomlogFlag = 0

# File descriptor for alerts/service events log file handle
global fd 


#########-------------------------------------------------------------------


##################################################################
# Init module for logging into a file.
#
##################################################################
def initialize_alert_logging():
	global fd
	# Initialize the log file path, log format and log level
	logfiledir = os.getcwd() + os.sep + "ovgd_logs"
	#print("Printing log file directory")
	#print("logfiledir - {}".format(logfiledir))
	
	if not os.path.isdir(logfiledir):
		os.makedirs(logfiledir)

	logfile = logfiledir + os.sep +"ovgd_logs.log"
	if os.path.exists(logfile):
		fStats = os.stat(logfile)
		
		if fStats.st_size >= 10240000:
			#Backing up logfile if size is more than 1MB
			timestamp = '{:%Y-%m-%d_%H_%M_%S}'.format(datetime.now())
			#Backup logfile
			os.rename(logfile,logfiledir + os.sep + 'ovgd_logs_'+ timestamp +".log")
			
			#Create and open a new file
			fd = open(logfile, "w+")
		else:
			fd = open(logfile, "a")
	else:
		#Open the file
		fd = open(logfile, "w+")
		
	return 0


##################################################################
# Function to convert alerts into  syslog format and write into a file
#
##################################################################
def log_alerts_custom(jsonObj):
	
	retVal = 0
	global fd
	
	print("Logging alerts")
	
	created_date = jsonObj['created']
	severity = jsonObj['severity']
	uri = jsonObj['uri']
	associated_rsc = jsonObj['associatedResource']['associationType']+jsonObj['associatedResource']['resourceCategory']+jsonObj['associatedResource']['resourceName']+jsonObj['associatedResource']['resourceUri']+jsonObj['alertState']+jsonObj['physicalResourceType']
	desc=jsonObj['correctiveAction']
	
	if desc == None :
		convertedStr = str(desc)
		desc = jsonObj['description'] + convertedStr
	else:
		desc = jsonObj['description']+jsonObj['correctiveAction']
	
	fd.write('OVGD_Alerts -' + " : "+str(created_date)+" "+str(severity)+" "+str(uri)+" "+"-"+str(associated_rsc)+" "+"["+desc+"]"+" "+"\n\n\n")
	fd.flush()
	
	return retVal

	
##################################################################
# Function to convert alerts into  syslog format and write into a file
#
##################################################################
def log_service_events_custom(jsonObj):
	
	retVal = 0
	global fd
	
	print("Logging events")
	
	created_date = jsonObj['created']
	severity = jsonObj['severity']
	uri = jsonObj['uri']
	associated_rsc = jsonObj['associatedResource']['associationType']+jsonObj['associatedResource']['resourceCategory']+jsonObj['associatedResource']['resourceName']+jsonObj['associatedResource']['resourceUri']+jsonObj['alertState']+jsonObj['physicalResourceType']
	desc = jsonObj['correctiveAction']
	
	serviceEventDetails = 	"Primary_Contact : " + jsonObj['serviceEventDetails']['primaryContact'] + ". Case_ID : " + jsonObj['serviceEventDetails']['caseId'] + \
							". Remote_Support_State: " + jsonObj['serviceEventDetails']['remoteSupportState']
	
	strSeparator = " - "
	
	if desc == None :
		convertedStr = str(desc)
		desc = jsonObj['description'] + strSeparator + convertedStr
	else:
		desc = jsonObj['description'] + strSeparator + jsonObj['correctiveAction']
		
	
	fd.write('OVGD_Service_Events ' + strSeparator + str(created_date) + strSeparator + str(serviceEventDetails)+ strSeparator + str(severity) + \
	strSeparator + str(uri) + strSeparator + str(associated_rsc) + strSeparator + " [" + desc + "] "+" "+"\n\n")
	
	fd.flush()
	
	return retVal


##################################################################
# Cleanup activities
##################################################################
def cleanup_before_exiting():
	global fd
	
	# Close the log file pointer
	fd.close()
	return 0


##################################################################
# Pass the alert and get back the payload to be sent 
# to NetCool via SDDC microservices API
#
##################################################################
def log_alerts_full(alert):
	# Empty payload and content holders
	#
	payload = {}
	actionData = {}
	
	# Assigning values from alert body
	# 
	actionData["serviceEventDetails"]				   = alert["serviceEventDetails"]
	actionData["created"]                              = alert["created"]
	actionData["correctiveAction"]                     = alert["correctiveAction"]
	actionData["payloadTypeID"]                        = alert["alertTypeID"]
	actionData["activityUri"]                          = alert["activityUri"]
	actionData["modified"]                             = alert["modified"]
	actionData["physicalResourceType"]                 = alert["physicalResourceType"]
	actionData["assignedToUser"]                       = alert["assignedToUser"]
	
	#actionData["changeLog"]                            = alert["changeLog"]
	if len(alert["changeLog"]) > 0:
		#Get the most recent change log 
		actionData["changeLog_userEntered"]                = alert["changeLog"][0]["userEntered"]
		actionData["changeLog_notes"]                      = alert["changeLog"][0]["notes"]
		actionData["changeLog_created"]                    = alert["changeLog"][0]["created"]
		actionData["changeLog_uri"]                        = alert["changeLog"][0]["uri"]
		actionData["changeLog_username"]                   = alert["changeLog"][0]["username"]

	else:
		# Assign NULL to the respective keys
		payload["changeLog_userEntered"]                = ""
		payload["changeLog_notes"]                      = ""
		payload["changeLog_created"]                    = ""
		payload["changeLog_uri"]                        = ""
		payload["changeLog_username"]                   = ""

		
	actionData["description"]                          = alert["description"]
	actionData["healthCategory"]                       = alert["healthCategory"]
	actionData["eTag"]                                 = alert["eTag"]
	actionData["severity"]                             = alert["severity"]
	actionData["resourceUri"]                          = alert["resourceUri"]
	actionData["urgency"]                              = alert["urgency"]
	actionData["serviceEventSource"]                   = alert["serviceEventSource"]
	actionData["uri"]                                  = alert["uri"]
	actionData["category"]                             = alert["category"]
	actionData["lifeCycle"]                            = alert["lifeCycle"]
	actionData["payloadState"]                         = alert["alertState"]
	actionData["clearedByUser"]                        = alert["clearedByUser"]
	actionData["clearedTime"]                          = alert["clearedTime"]
	actionData["type"]                                 = alert["type"]
	actionData["associatedResource_resourceName"]      = alert["associatedResource"]["resourceName"]
	actionData["associatedResource_resourceCategory"]  = alert["associatedResource"]["resourceCategory"]
	actionData["associatedResource_resourceUri"]       = alert["associatedResource"]["resourceUri"]
	actionData["associatedResource_associationType"]   = alert["associatedResource"]["associationType"]
	actionData["associatedEventUris"]                  = alert["associatedEventUris"][0]
	actionData["resourceID"]                           = alert["resourceID"]
	actionData["id"]                                   = alert["id"]
	actionData["originalUri"]                          = alert["originalUri"]
	actionData["status"]                               = alert["status"]
	actionData["appluri"]                              = alert["appluri"]
	actionData["applianceName"]                        = alert["applianceName"]
	actionData["applianceLocation"]                    = alert["applianceLocation"]
	actionData["associatedResourceName"]               = alert["associatedResourceName"]
	actionData["associatedResourceOriginalUri"]        = alert["associatedResourceOriginalUri"]
	actionData["applianceModel"]                       = alert["applianceModel"]
	actionData["applianceVersion"]                     = alert["applianceVersion"]	

	payload["generateIncidentOnFailue"] = "true"
	payload["policy_name"] = "IT-OneView-SOAPEvent"
	payload["actionData"] = actionData
	payload["action"] = "send_alert"
	
	#print("json alert payload - {}".format(json.dumps(payload)))
	global fd
	fd.write(json.dumps(payload, indent=4, sort_keys=False) + "\n")
	fd.flush()
	
	return 0



##################################################################
# Pass the service event and get back the payload to be sent 
# to NetCool via SDDC microservices API
#
##################################################################
def log_service_events_full(serviceEvent):
	# Empty payload and content holders
	#
	payload = {}
	actionData = {}
	
	# Assigning values from service event body
	# 
	payload["type"]										= serviceEvent["type"]
	payload["serviceEventSource"]                       = serviceEvent["serviceEventSource"]
	payload["serviceEventDetails_primaryContact"]       = serviceEvent["serviceEventDetails"]["primaryContact"]
	payload["serviceEventDetails_caseId"]               = serviceEvent["serviceEventDetails"]["caseId"]
	payload["serviceEventDetails_remoteSupportState"]   = serviceEvent["serviceEventDetails"]["remoteSupportState"]
	payload["resourceUri"]                              = serviceEvent["resourceUri"]
	payload["physicalResourceType"]                     = serviceEvent["physicalResourceType"]
	payload["alertState"]                               = serviceEvent["alertState"]
	payload["associatedResource_resourceUri"]           = serviceEvent["associatedResource"]["resourceUri"]
	payload["associatedResource_resourceCategory"]      = serviceEvent["associatedResource"]["resourceCategory"]
	payload["associatedResource_associationType"]       = serviceEvent["associatedResource"]["associationType"]
	payload["associatedResource_resourceName"]          = serviceEvent["associatedResource"]["resourceName"]
	payload["severity"]                                 = serviceEvent["severity"]
	payload["eTag"]                                     = serviceEvent["eTag"]
	payload["created"]                                  = serviceEvent["created"]
	payload["modified"]                                 = serviceEvent["modified"]
	payload["alertTypeID"]                              = serviceEvent["alertTypeID"]
	payload["urgency"]                                  = serviceEvent["urgency"]
	payload["lifeCycle"]                                = serviceEvent["lifeCycle"]
	payload["activityUri"]                              = serviceEvent["activityUri"]
	payload["resourceID"]                               = serviceEvent["resourceID"]
	payload["associatedEventUris"]                    	= serviceEvent["associatedEventUris"][0]
	payload["assignedToUser"]                           = serviceEvent["assignedToUser"]
	
	if len(serviceEvent["changeLog"]) > 0:
		#Get the most recent change log 
		payload["changeLog_userEntered"]                = serviceEvent["changeLog"][0]["userEntered"]
		payload["changeLog_notes"]                      = serviceEvent["changeLog"][0]["notes"]
		payload["changeLog_created"]                    = serviceEvent["changeLog"][0]["created"]
		payload["changeLog_uri"]                        = serviceEvent["changeLog"][0]["uri"]
		payload["changeLog_username"]                   = serviceEvent["changeLog"][0]["username"]

	else:
		# Assign NULL to the respective keys
		payload["changeLog_userEntered"]                = ""
		payload["changeLog_notes"]                      = ""
		payload["changeLog_created"]                    = ""
		payload["changeLog_uri"]                        = ""
		payload["changeLog_username"]                   = ""

	payload["clearedByUser"]                            = serviceEvent["clearedByUser"]
	payload["clearedTime"]                              = serviceEvent["clearedTime"]
	payload["correctiveAction"]                         = serviceEvent["correctiveAction"]
	payload["healthCategory"]                           = serviceEvent["healthCategory"]
	payload["description"]                              = serviceEvent["description"]
	payload["category"]                                 = serviceEvent["category"]
	payload["uri"]                                      = serviceEvent["uri"]
	payload["id"]                                       = serviceEvent["id"]
	payload["originalUri"]                              = serviceEvent["originalUri"]
	payload["status"]                                   = serviceEvent["status"]
	payload["appluri"]                                  = serviceEvent["appluri"]
	payload["applianceName"]                            = serviceEvent["applianceName"]
	payload["applianceLocation"]                        = serviceEvent["applianceLocation"]
	payload["associatedResourceName"]                   = serviceEvent["associatedResourceName"]
	payload["associatedResourceOriginalUri"]            = serviceEvent["associatedResourceOriginalUri"]
	payload["applianceModel"]                           = serviceEvent["applianceModel"]
	payload["applianceVersion"]                         = serviceEvent["applianceVersion"]
	
	payload["generateIncidentOnFailue"] = "true"
	payload["policy_name"] = "IT-OneView-SOAPEvent"
	payload["actionData"] = actionData
	payload["action"] = "send_alert"
	
	#print("json service event payload - {}".format(json.dumps(payload)))
	global fd		
	fd.write(json.dumps(payload, indent=4, sort_keys=False) + "\n")
	fd.flush()
	
	return 0


##################################################################
# Wrapper function to process alert/event. 
# Checks the flag and calls appripriately.
##################################################################
def log_notification(alert):
	retVal = 0
		
	temp = str(alert["serviceEventSource"]).upper()
	if(temp == "TRUE"):
		if fullOrCustomlogFlag == 0:
			retVal = log_service_events_full(alert)
		else:
			retVal = log_service_events_custom(alert)
	else:
		if fullOrCustomlogFlag == 0:
			retVal = log_alerts_full(alert)
		else:
			retVal = log_alerts_custom(alert)		
		
	'''
	payload1 = {"key":"value"}
	uglyjson = '{"firstnam":"James","surname":"Bond","mobile":["007-700-007","001-007-007-0007"]}'
	print("bool(payload1) - {}".format(bool(payload1)))
	print("payload1 - {}".format(json.dumps(payload1)))
	parsed = json.loads(uglyjson)
	print(json.dumps(uglyjson, indent=4, sort_keys=False))
	sys.exit(0)
	'''
	
	return retVal


##################################################################
# Init the SDDC module
# First API which is to be exposed to application
##################################################################
def init(logger_module):

	retVal = 0 # Assuming all goes well. 
	#print("module_init - I am in logging module")
	
	global logging	
	logging = logger_module
	
	initialize_alert_logging()
	
	return retVal


##################################################################
# Post the events/alerts to NetCool via SDDC microservices
# Second API which is to be exposed to application
##################################################################
def execute(alert):
	retStatus = log_notification(alert)
	return retStatus
	

##################################################################
# Post the events/alerts to NetCool via SDDC microservices
# Second API which is to be exposed to application
##################################################################
def cleanup():
	retStatus = 0 # Assuming all good
	retStatus = cleanup_before_exiting()
	return retStatus


#########-------------------------------------------------------------------


