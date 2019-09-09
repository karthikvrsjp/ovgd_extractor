# Python extract routine for extracting alert/event detail from HPE OneView Global Dashboard

**Problem Statement**

Some of our customers are looking for solution to extract alerts and service events and publish to their monitoring software. At present, we create a log file of the alerts and service events in this utility, but the same can be extrapolated to integrate with their 3rd party or custom tools. 

**Solution design**

To address their needs, we developed a extractor using Python which collects alerts and service events. Extractor does necessary processing of collected data before logging it into log file for consumption later. An iteration of the extract routine will connect to the instance of HPE OneView Global Dashboard configured in config.json and exract the critical alerts information as well as the service event information that is available within this instance and writes this information to the syslog file. Each invocation will complete one iteration. There will be one extractor running for each OneView Global dashboard appliance.

This solution can be seamlessly extended to monitor all infrastructure supported by HPE OneView Global Dashboard.


**End outcome**

Once the data is logged into logfile in project folder, user can view alert and service event status and can start consuming from the logfile directly. The solution can easily be integrated into any 3rd party monitoring solutions like Nagios, Splunk or inhouse monitoring tools via respective APIs. The solution we developed is a more generic monitoring solution and doesn't limit to any particular customer. The plugin can be deployed on any Linux based server or a docker container.


## Getting Started

System requirements - Centos7 machine for plugin deployment, python3.6 or later.

### Prerequisites and Installing the components of test environment

Setting up the Linux  machine with python3.6 and relevant packages. 
```
1. To setup python3.6
	Step 1: Open a Terminal and add the repository to your Yum install.
	$ sudo yum install -y https://centos7.iuscommunity.org/ius-release.rpm
	
	Step 2: Update Yum to finish adding the repository.
	$ sudo yum update
	
	Step 3: Download and install Python.		
	$ sudo yum install -y python36u python36u-libs python36u-devel python36u-pip
	
	Step 4: Once these commands are executed, simply check if the correct version of Python has been installed by executing the following command:
	$ python3.6 -V
	
	
2. To setup relevant python3.6 modules. 
	Step1: The required python3.6 modules and their versions are mentioned in the file requirements.txt; Install them using the below command.
	$ pip3 install -r requirements.txt
```

### Files to be modified - ***Relevant environment variables need to be exported***.

Edit the following information:
```
Export the following details - ovgd_host, username, password, authLoginDomain, number of events to be processed (numAlertsProcessedAtStart) when running for the first time.
```

The next section mentions about how to do a dry run of the setup.

## Running the tests

Our python plugin can be deployed in one of the following 3 ways:
```
1. 	As a manual standalone script whenever required
2.	As a cron job to do the processing periodically
```

> Ensure OneView global dashaboard is up and running. Ping test the appliance to see if it is reachable. 

`$ ping <OVGD IP Address>`


## Deployment

> Modify inputs in file ***config.json***.


### To run as standalone script

Execute as follows:-

```
$ python3.6 main.py -i <relevant_module.py> ; Eg: python3.6 main.py -i splunk_module.py
Note: Please note python3.6 is the name of the installed binary and in your environment, it could be named python due to runtime environment differences

On successful completion of the script, the number of alerts and the timestamp of the last alert processed will be displayed. On subsequent re-runs, all new alerts generated since the timestamp of the last alert will be processed.

```

### To see logs

`$ tail -f ovgd_logs/ovgd_logs.log`


### Daemon configuration

Execute as follows:-

```
The provided extract routine will need to be executed multiple times in order to retrieve all the alerts that are posted between execution runs. This manual task can be automated using a job scheduler. HPE recommends the usage of job scheduler which provides the ability to configure schedules at a frequency that is desirable to the organization. At a minimum a job scheduler that supports the execution of a job on a per minute basis would be ideal. 

The Linux Operating System provides a job scheduler service named ‘cron’. This job scheduler does have the capability to execute a job every minute if so desired or a time interval that is suitable to your needs.

Further details on cron and its crontab configuration can be obtained either on the system man pages or via a web search. 

Rundeck is an Open Source job scheduler which is an option to consider. More information at rundeck.org


```

## Built With

* OneView Global Dashboard- Appliance which is used to configure and manage the servers
* Python3.6 - Scripting language used
* Centos7 - OS on which the code is deployed and tested


## Versioning

We use [GitHub](http://github.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **HPE Global Solutions Engineering** 

See also the list of [contributors](https://github.hpe.com/GSE/oneview-nagios/graphs/contributors) who participated in this project.

## License

(C) Copyright (2018) Hewlett Packard Enterprise Development LP

## Acknowledgments

