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
import logging
import logging.handlers
import time 
from time import sleep
from dateutil import parser as dateParser
import os
import argparse
from datetime import datetime

import base64
import ast
import sys


global gLastAlertTimestampFile, gMissedAlertsInfoFile, gServersURItoHostnamesMap, gOvgdDir
global module_init, module_execute, module_cleanup

# Suppress warning - InsecureRequestWarning: Unverified HTTPS request is being made
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Setting logging level of "requests" module
# This is to avoid info and debug messages of requests module being printing b/w application log messages. 
#
logging.getLogger("requests").setLevel(logging.WARNING)


##################################################################
# Function to get auth token for OVGD
#
##################################################################
def get_ovgd_token(ovgdConfig):
	
	req_url = "https://{}/rest/login-sessions".format(ovgdConfig["ovgd_host"])	
	headers = { 'Content-Type': 'application/json', 'X-Api-Version': '2' }	
	body = { 'authLoginDomain': ovgdConfig["authLoginDomain"], 'userName': ovgdConfig["username"], 'password': ovgdConfig["password"] }
	
	#print(json.dumps(body, indent=4))
	#print(req_url)
	resp = requests.post(req_url, headers=headers, data=json.dumps(body), verify=False)
    
	if (resp.status_code != 200):
		logging.error("Failed to retrive TOKEN..! Status code = {}. Error Message = {}.".format(resp.status_code, resp.text))
		exit(1)

	resp_dict = resp.json()

	return resp_dict["token"]


##################################################################
# Init the logging module.
# The log file is backed up if the size is > 1 MB
##################################################################
def initialize_logging(ovgdIP, loggingLevel='WARNING'):
	# Initialize the log file path, log format and log level
	logfiledir = os.getcwd() + os.sep + "logs"
	#print("Debug logfiledir - {}".format(logfiledir))
	if not os.path.isdir(logfiledir):
		os.makedirs(logfiledir)
		
	logfile = logfiledir + os.sep + "OVGD_NETCOOL_{}.log".format(ovgdIP)
	if os.path.exists(logfile):
		fStats = os.stat(logfile) 
		if fStats.st_size >= 1024000:
			#Backing up logfile if size is more than 1MB and creating an empty file for use. 
			timestamp = '{:%Y-%m-%d__%H-%M-%S}'.format(datetime.now())
			os.rename(logfile,logfiledir + os.sep + 'OVGD_NETCOOL_{}_'.format(ovgdIP)+ timestamp +".log")
			open(logfile, 'a').close()
	else:
		#Create empty logfile
		open(logfile, 'a').close()

	# Init the logging module with default log level to INFO. 
	logging.basicConfig(filename=logfile, format='%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%d-%m-%Y:%H:%M:%S', level=loggingLevel)
	

##################################################################
# Function to backup ID of alert if its processing is failed
#
##################################################################
def backup_alert_for_processing_next_time(alertID):
	retVal = 0
	## File "gLastAlertTimestampFile" is supplied as global variable.
	## The same file is used as reference for reading and updating 
	## the last processed event's timestamp
	##
	try:		
		if os.path.exists(gMissedAlertsInfoFile):
			f = open(gMissedAlertsInfoFile, 'a')
		else:
			f = open(gMissedAlertsInfoFile, 'w')
		
		print("Updating missed alert entry")
		logging.info("Updating missed alert entry")
		f.write(alertID+"\n")
		f.close
	except Exception as e:
		logging.error("Unable to update falied alert's ID{}. Reason  - {}.".format(alertID, e))
		retVal = 1

	return retVal

	
##################################################################
# Function to change resource names appropriately
#
##################################################################
def alert_name_change(Host, auth_token, alert, serverMap):
	#----------------------
	if alert["physicalResourceType"] == "server-hardware":
		serverID = alert["resourceUri"].split("/")[-1]
		
		if serverID in serverMap.keys():
			if (serverMap[serverID] != None and len(serverMap[serverID]) > 0):
				print("ServerID - {} : Hostname - {}".format(serverID, serverMap[serverID]))
				alert["associatedResource"]["resourceName"] = serverMap[serverID]
			else:
				print("Hostname not assigned for serverID - {}".format(serverID))
		else: 
			print("Server key - {}; not present. Recreate server map.".format(serverID)) 
			# print("Alert - {}".format(alert))
			
			# Recreate the server map with refreshFalg set. 
			serverMap = get_server_hardware_hostname_map(Host, auth_token, 1)
			if serverID in serverMap.keys(): 
				if (serverMap[serverID] != None and len(serverMap[serverID]) > 0):
					print(" (2nd time) ServerID - {} : Hostname - {}".format(serverID, serverMap[serverID]))
					alert["associatedResource"]["resourceName"] = serverMap[serverID]
				else:
					print("Hostname not assigned for serverID - {}".format(serverID))
				
			else: 
				print("Key not present now also - {}".format(serverID)) 
				print("Alert from server with UUID - {}. Server not present in OVGD".format(serverID))
				logging.warning("Alert from server with UUID - {}. Server not present in OVGD".format(serverID))
				alert["associatedResource"]["resourceName"] = "Non-existent-hardware"		#Tad_TBD
				
	elif alert["physicalResourceType"] == "appliance":
		alert["associatedResource"]["resourceName"] = alert["applianceLocation"]
		print("Alert from {}. Name changed to - {}.".format(alert["physicalResourceType"], alert["associatedResource"]["resourceName"]))
	else:
		print("Alert is not from server-hardware or appliance but from {}. Retaining the name as it is - {}.".format(alert["physicalResourceType"], alert["associatedResource"]["resourceName"]))
	#-------------------------
	
	return alert, serverMap
	
	

##################################################################
# Function to get all alerts
#
##################################################################
def alerts_and_events_process_firsttime(Host, auth_token, numAlertsProcessedAtStart):
	
	## Initializing the counters
	allAlerts = [] 	# Place holder for all the alerts	
	startIdx = 0  	# Starting from index = 0
	countOfEvents = 500	# Fetching 500 events per pass (Max number of events that can be fetched at a time)
	flag = False	# Flag indicating whether we have processed all teh relevant alerts
	
	headers = { 'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': auth_token }
	
	while (True):
		## Sample URL: https://10.10.10.10/rest/resource-alerts?start=0&count=500&sort=created:desc
		##
		req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(Host, startIdx, countOfEvents)
		
		resp = requests.get(req_url, headers = headers, verify = False)
		if (resp.status_code != 200):
			logging.error("Failed to alerts.! Status code = {}. Error Message = {}.".format(resp.status_code, resp.text))
			exit(1)
		jsonResp = resp.json()
		
		alertsNow = jsonResp["members"]
		lenCurrentAlerts = len(alertsNow)
		
		for alert in alertsNow:
			allAlerts.append(alert)
			
			if ( (jsonResp["count"] == 0) or (len(allAlerts) >= numAlertsProcessedAtStart) ):
				# We have processed all the relevant events. Breaking from the loop. 
				flag = True
				break # From for loop
		
		if ( (jsonResp["count"] == 0) or (len(allAlerts) >= numAlertsProcessedAtStart) ):
			# We have processed all the relevant events. Need not read anymore alerts.
			break # From while loop
			
		startIdx += jsonResp["count"]
		sleep(0.5) # A small pause before continuing
					
	allAlerts.reverse() # This is done to log events in order of occurance. If we need to log the latest event first, we can comment this. 
	if len(allAlerts) > 0:
		print("Completed reading of all the relevant alerts")
	else:
		print("No alerts to process")
	
	serverMap = get_server_hardware_hostname_map(Host, auth_token, 0)
	#print("keys - {}".format(serverMap.keys()))
	
	procAlerts = 0
	for alert in allAlerts:
		
		alert, serverMap = alert_name_change(Host, auth_token, alert, serverMap)
		
		retStatus = module_execute(alert)
		if(retStatus == 0): # Keeping track of success and failed alerts
			procAlerts += 1
		else:
			logging.warning("Failed  to process alert with ID - {}".format(alert["id"]))
			backup_alert_for_processing_next_time(alert["id"])
	
	logging.info("First time alerts to be processed - {}; Alerts successfully processed - {}".format(len(allAlerts), procAlerts))
				
	# Updating the timestamp of last processed alert
	update_alert_timestamp(alert["created"])
	
	return 0


##################################################################
# Function to get all alerts from last processed alert
#
##################################################################
def get_current_ovgd_alerts_and_events(Host, auth_token, lastAlertTime):
	headers = { 'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': auth_token }
	
	nextPageUri = 1 # Set this to TRUE initially. 
	
	## Initializing the counters
	relevantAlerts = [] # Place holder for the alerts	
	startIdx = 0  		# Starting from index = 0
	countOfEvents = 500	# Trying to fetch 500 events per pass (Max number of events that can be fetched at a time)
	flag = False
	
	while (1):
		## Sample URL: https://10.10.10.10/rest/resource-alerts?start=0&count=500&sort=created:desc
		##
		req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(Host, startIdx, countOfEvents)
		
		resp = requests.get(req_url, headers = headers, verify = False)
		if (resp.status_code != 200):
			logging.error("Failed to alerts.! Status code = {}. Error Message = {}.".format(resp.status_code, resp.text))
			exit(1)
		jsonResp = resp.json()
		
		presentAlerts = jsonResp["members"]
		
		if (jsonResp["count"] > 0): # If there are some events, proceed.
			for alert in presentAlerts:
				thisAlertTime = dateParser.parse(alert["created"])
				
				if (thisAlertTime <= lastAlertTime):
					# We have received all the events. Breaking from the loop. 
					flag = True
					break
				else:
					relevantAlerts.append(alert)
				
			if (flag == True):
				break # from while loop
			else:
				startIdx += jsonResp["count"]
				sleep(0.5) # A small pause before continuing <TDB>
		else:
			logging.info("Events are already read and processed.")
			
	lenArray = len(relevantAlerts)
	
	if lenArray > 0:
		relevantAlerts.reverse() # To process alerts in order of occurance. Else this is not required. 

	return relevantAlerts
		
##################################################################
# Function to get all alerts
#
##################################################################
def process_alerts_if_any_from_lasttime(ovgdHost, auth_token):
	
	headers = { 'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': auth_token }
	
	# List of alerts which are not processed in this routine
	newMissedAlerts = []
	
	## There are any events which were missed processing in previous run,
	## they will be logged in the file and processed in subsequent runs. 
	##
	## Checking if there are any alerts missed processing last time
	#
	
	if os.path.exists(gMissedAlertsInfoFile):
		logging.info("Processing alerts which were not processed in previous run")
		print("Processing alerts which were not processed in previous run")
		with open(gMissedAlertsInfoFile) as f:
			missedAlertIDs = f.readlines()

		# You may also want to remove whitespace characters like `\n` at the end of each line
		missedAlertIDs = [x.strip() for x in missedAlertIDs]
		logging.info("Failed to process {} events from previous run. Processing now.".format(len(missedAlertIDs)))
		logging.info("Details - {} .".format(missedAlertIDs))
		f.close()

		serverMap = get_server_hardware_hostname_map(ovgdHost, auth_token, 0)
	
		# Process all the alerts that we have discovered now
		for id in missedAlertIDs:
			URI = "https://{}/rest/resource-alerts/{}".format(ovgdHost, id)
			#req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(ovgdHost, startIdx, countOfEvents)
			
			
			resp = requests.get(URI, headers = headers, verify = False)
			if (resp.status_code != 200):
				logging.error("Failed to retrive alert with ID - {}. Status code = {}. Error Message = {}.".format(id, resp.status_code, resp.text))
				#exit(1) 
			else:
				# Process the alert
				alert = resp.json()	
				
				alert, serverMap = alert_name_change(ovgdHost, auth_token, alert, serverMap)				
				
				
				# Notify and check if the alert went through.
				retStatus = module_execute(alert)
				if(retStatus == 0):
					retStatus = 0 # When print is removed, we can change the logic to have a debug or info message or something else
				else:
					# Failed to send alert. Append it to list to cache again in "/tmp/ovgd_extr/missed_alerts" file. 
					#
					newMissedAlerts.append(alert["id"])
					print("URI - {}".format(alert["id"]))
					
		
		# Storing back the alert ids which we failed to send. 
		if(len(newMissedAlerts) > 0):
			fd = open(gMissedAlertsInfoFile, 'w')
			logging.warning("Still failed to send some alerts from cached file ({} of them). Cache-ing them back again.".format(len(newMissedAlerts)))
			for alertID in newMissedAlerts:
				fd.write(alertID+"\n")
			fd.close	
		else:
			os.remove(gMissedAlertsInfoFile)
	else:
		#print("No events/alerts missed from processing")
		logging.info("No events/alerts missed from processing")
	
			

##################################################################
# Function to get all alerts
#
##################################################################
def process_alerts_and_service_events(ovgdHost, auth_token, lastAlertTime, numAlertsProcessedAtStart):
	
	if lastAlertTime == -1:
		# Running for the first time as the timestamp is not logged in /tmp/ovgd_extr 
		#
		logging.info("Running for the first time. Configured to process upto {} of most recent alerts (or less) of the total alerts present".format(numAlertsProcessedAtStart))
		alerts_and_events_process_firsttime(ovgdHost, auth_token, numAlertsProcessedAtStart)
		
	else:
		# Alerts are processed till sometime back. Processing the remaining alerts
		#
		process_alerts_if_any_from_lasttime(ovgdHost, auth_token)
		
		currentAlerts = get_current_ovgd_alerts_and_events(ovgdHost, auth_token, lastAlertTime)
		
		procAlerts = 0
		serverMap = get_server_hardware_hostname_map(ovgdHost, auth_token, 0)
	
		if(len(currentAlerts) > 0):
			for alert in currentAlerts:	
				alert, serverMap = alert_name_change(ovgdHost, auth_token, alert, serverMap)

				retStatus = module_execute(alert)
									
				# Keeping track of success and failed alerts
				if(retStatus == 0):
					procAlerts += 1
				else:
					backup_alert_for_processing_next_time(alert["id"])
					
			logging.info("New alerts to be processed - {}; Alerts successfully processed - {}".format(len(currentAlerts), procAlerts))
			
			# Updating the timestamp of last alert processed
			update_alert_timestamp(alert["created"])
		else:
			logging.info("No new alerts for processing")
	

	
##################################################################
# Update the timestamp of last sent alert. 
# 
##################################################################
def update_alert_timestamp(timeStamp):

	retVal = 0
	## File "gLastAlertTimestampFile" is supplied as global variable.
	## The same file is used as reference for reading and updating 
	## the last processed event's timestamp
	##
	try:
		f = open(gLastAlertTimestampFile, 'w')
		f.write(timeStamp)
		f.close
	except Exception as e:
		logging.error("Failed to update timestamp of last sent alert - {}. Might continue processing alerts from beginning.".format(e))
		retVal = 1
								
	return retVal


##################################################################
# Get timestamp of the last sent alert. 
# 	If the timestamp is not present, we assume that the script is - 
#	starting for the first-time and send all the alerts. 
##################################################################
def get_last_sent_alert_timestamp():
	
	lastAlertTime = -1 # Assuming it is not existing. Assign appropriately if existing. 
	
	## Open the file in read mode if exists and return the timestamp
	##
	if os.path.exists(gLastAlertTimestampFile):
		try:
			f = open(gLastAlertTimestampFile, 'r')
			alertTS = f.readline()
			lastAlertTime = dateParser.parse(alertTS)
		except Exception as e:
			logging.error("Failed to read timestamp of last sent alert - {}".format(e))
			logging.error("Assuming running for the first time.")			
						
							
	return lastAlertTime


##################################################################
# Function to read server-map file (server h/w URIs to hostnames map)
# This function can be called for 2 reasons:
#	- To create and get the server map when application is launched for the first time
#	- To read the server map stored in the file when application is launched subsequently
#	- To create and get the server map when hardware URI is not found in the map \ 
#	 (This condition arises when the server hardware is added newly)
##################################################################
def get_server_hardware_hostname_map(ovgdHost, authToken, refreshFlag):
	
	if (refreshFlag) and os.path.exists(gServersURItoHostnamesMap):
		os.remove(gServersURItoHostnamesMap)
		
	# Make sure the map file exists. Else, create a new one. 
	if not os.path.exists(gServersURItoHostnamesMap):
		create_server_hardware_hostname_map(ovgdHost, authToken)
	
	with open(gServersURItoHostnamesMap) as json_file:	
		serverMap = json.load(json_file)
	
	return serverMap
	
##################################################################
# Function to read hosts and create a dictionary of URL to hostnames
#
##################################################################
def create_server_hardware_hostname_map(ovgdHost, authToken):
	retVal = 0
	nextPageUri = 1 # Set this to TRUE initially. 
	
	## Initializing the counters
	totalServers = [] # Place holder for the alerts	
	startIdx = 0  		# Starting from index = 0
	numServersToRead = 500	# Trying to fetch 500 events per pass (Max number of objects that can be fetched at a time)
	flag = False	# Flag to determine continue to find servers or to break from while() loop
	serverMap = {}
	headers = { 'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': authToken }
	
	while (1):
		## Sample URL: https://10.10.10.10/rest/server-hardware?start=0&count=500
		##
		req_url = "https://{}/rest/server-hardware?start={}&count={}".format(ovgdHost, startIdx, numServersToRead)
		
		resp = requests.get(req_url, headers = headers, verify = False)
		if (resp.status_code != 200):
			logging.error("Failed to read server details.! Status code = {}. Error Message = {}.".format(resp.status_code, resp.text))
			exit(1)
		jsonResp = resp.json()
		
		presentServers = jsonResp["members"]
		
		if (jsonResp["count"] > 0): # If there are some more servers, proceed.
			for server in presentServers:
				#print("Server - {}".format(server))
				#key = id = server["originalUri"].split("/")[-1] # "originalUri" = "/rest/server-hardware/30373737-3237-4D32-3230-313530314752";
				key = server["originalUri"].split("/")[-1] # "originalUri" = "/rest/server-hardware/30373737-3237-4D32-3230-313530314752"; Need only last part.
				value = server["serverName"]
				serverMap[key] = value
								
			if (jsonResp["count"] < numServersToRead):
				# We have mapped all the server-hardware. Breaking from the loop. 
				#logging.info("We have mapped all the server-hardware.")
				flag = True
				break
			else:
				startIdx += jsonResp["count"]
				sleep(0.1) # A small pause before continuing <TBD>
		else:
			logging.info("We have mapped all the server-hardware.")
			
	with open(gServersURItoHostnamesMap, 'w') as serverMapFile:
		json.dump(serverMap, serverMapFile)
	
	return retVal


##################################################################
# Validate OVGD config extracted from environment variables
##################################################################
def validate_ovgd_config(ovgdConfig):
	
	retStatus = 0 # Assuming all details are available
	
	if ovgdConfig["ovgd_host"] is None or "":
		logging.error('ovgd_host environment variable not set')
		retStatus = 1
		
	if ovgdConfig["username"] is None or "":
		logging.error('ovgd_username environment variable not set')
		retStatus = 1
		
	if ovgdConfig["password"] is None or "":
		logging.error('ovgd_password environment variable not set')
		retStatus = 1

	if ovgdConfig["authLoginDomain"] is None or "":
		logging.error('ovgd_authLoginDomain environment variable not set')
		retStatus = 1
		
	if ovgdConfig["numAlertsProcessedAtStart"] is None or "":
		logging.error('ovgd_numAlertsProcessedAtStart environment variable not set')
		retStatus = 1
		
	return retStatus



##################################################################
# Get OVGD config details from environment variables
##################################################################
def get_ovgd_config_from_env():

	ovgd_config = {}
	
	# Ensure that all the config variables are exported to env. 
	# If a particular variable is not present, it will return a NULL string and that will be assigned to that config variable
	ovgd_config["ovgd_host"] = os.environ.get('ovgd_host')
	ovgd_config["username"] = os.environ.get('ovgd_username')
	#ovgd_config["password"] = os.environ.get('ovgd_password')
	tempPwd = os.environ.get('ovgd_password')
	tempPwd = base64.b64decode(tempPwd)
	tempPwd = tempPwd.decode('utf-8')
	ovgd_config["password"] = tempPwd
	ovgd_config["authLoginDomain"] = os.environ.get('ovgd_authLoginDomain')
	ovgd_config["numAlertsProcessedAtStart"] = os.environ.get('ovgd_extr_numAlertsProcessedAtStart')
	
	retStatus = validate_ovgd_config(ovgd_config)
	if retStatus != 0:
		logging.error("Please check OVGD config variables. Exiting.")
		sys.exit(1)
	
	return ovgd_config
	
##################################################################
# Init activities - Create a folder "/tmp/ovgd_extr" to store the following
# timestamp 	- last processed alert timestamp. 
# missed_alerts - Missed alert IDs.
# serverMap 	- Map of server URIs and its respective hostnames. 
##################################################################
def init_ovgd_extr():
	
	create_globals()
	
	# Creating the directory only if it does not exists. 
	if not os.path.isdir(gOvgdDir):
		retStatus = os.makedirs(gOvgdDir)
		
		if retStatus != None:
			logging.error("ERROR: Failed to create OVGD directory - {}".format(gOvgdDir))
			sys.exit(1)
	

##################################################################
# Validate supplied module 
#
##################################################################
def validate_input_module():

	# Move this part of the code into another function.
	
	global module_init, module_execute, module_cleanup

	moduleInitFlag = 0
	moduleExecuteFlag = 0
	moduleCleanupFlag = 0
	
	parser = argparse.ArgumentParser(add_help=True, description='Usage')
	parser.add_argument('-i', dest='input_file', required=True, help='SDDC module containing its implementation')
		
	# Check and parse the input arguments into python's format
	inputFile = parser.parse_args()
	
	inputModuleName = inputFile.input_file.split(".")[0]
	
	# Parsing file for details  
	with open(inputFile.input_file) as data_file:	
		node = ast.parse(data_file.read())
	
	functions = [n for n in node.body if isinstance(n, ast.FunctionDef)]

	for function in functions:
		if function.name == "init":
			moduleInitFlag = 1		
		
		if function.name == "execute":
			moduleExecuteFlag = 1		
		
		if function.name == "cleanup":
			moduleCleanupFlag = 1
			
	if not (moduleInitFlag and moduleExecuteFlag and moduleCleanupFlag):
		print("ERROR: Some or all of init(), execute() and cleanup() functions are missing in supplied module. Exiting.")
		sys.exit(1)
		
	else:
		#from inputModuleName import init, execute, cleanup
		print(inputModuleName)
		inputModule = __import__(inputModuleName)
		module_init = inputModule.init
		module_execute = inputModule.execute
		module_cleanup = inputModule.cleanup
		
		
##################################################################
# Function to assign appropriate values to global variables
#
##################################################################
def create_globals():
	global gLastAlertTimestampFile, gMissedAlertsInfoFile, gServersURItoHostnamesMap, gOvgdDir
	
	import tempfile
	tempDir = tempfile.gettempdir()
	
	gLastAlertTimestampFile = tempDir + os.sep + "ovgd_extr" + os.sep + "timestatmp"
	gMissedAlertsInfoFile = tempDir + os.sep + "ovgd_extr" + os.sep + "missed_alerts"
	gServersURItoHostnamesMap = tempDir + os.sep + "ovgd_extr" + os.sep + "server_map"
	gOvgdDir = tempDir + os.sep + "ovgd_extr"

##################################################################
# Main module
#
##################################################################
def main():
	
	# Create a folder "/tmp/ovgd_extr" to store relevant info
	init_ovgd_extr()
		
	try:
		# Get the config
		loggingLevel = os.environ.get('ovgd_extr_logging_level').upper()
		if loggingLevel is None or "":
			logging.error('extractor_logging_level environment variable not set. Configure it and restart.')
			sys.exit(1)
			
	except Exception as e:
		# We will not be able to log this message since logging is not yet initialized, hence printing
		logging.error(e)
		logging.error("Error in reading config from env variables. Export all of them and try again. Exiting")
		sys.exit(1)
		
	# Get OVGD auth token to login into system
	ovgdConfig = get_ovgd_config_from_env()	
	authToken = get_ovgd_token(ovgdConfig)	

	# Validate input module supplied by user
	validate_input_module()
	
	# If logging of alerts and service events in current directory is required..
	initialize_logging(ovgdConfig["ovgd_host"], loggingLevel)

	retStat = module_init(logging)
	if retStat != 0:
		print("ERROR: Module init failed. Please check relevant export variables.")
		sys.exit(1)
		
	# Timestamp of the last alert processed. We need to send all alerts post this.
	# If timestamp is not present, we need to send all the alerts from a specified time and update the last processed alert's timestamp. 
	#
	lastAlertTime = get_last_sent_alert_timestamp()
	process_alerts_and_service_events(ovgdConfig["ovgd_host"], authToken, lastAlertTime, int(ovgdConfig["numAlertsProcessedAtStart"]))
	
	module_cleanup()
	
	logging.info("OVGD extract utility exiting.\n")
	exit(0)
		

		
	
##################################################################
# Start module
#
##################################################################
if __name__ == "__main__":
	import sys

	sys.exit(main())
