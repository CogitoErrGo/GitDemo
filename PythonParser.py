import re
import json
from datetime import datetime
from datetime import date
from argparse import ArgumentParser

#Parsing command line arguments
parser = ArgumentParser()
parser.add_argument("-file", dest="logFilePath", help = "Open specified file")
parser.add_argument("--date","--DATE", dest="logDate", help = "Specify the date (YYYY-MM-DD) format for which you want to retrieve data")
args=parser.parse_args()

logFilePath=args.logFilePath
logDate=args.logDate
print (logDate)
yyyy=date.today().year #setting the year to current year since the given auth.log doesn't mention year

regexFP = '(Failed password for (.*?) from (.*?) port)'
regexRM = '(reverse mapping checking getaddrinfo for (.*?) \[(.*?)\])'


logDict = {}
logRevMap= {}

with open(logFilePath, "r") as file:
	for line in file:
		#Logging Failed Password Attempts
		for match in re.finditer(regexFP, line, re.S):
			user=match.group(2)
			dateUF= line[0:6]
			ip=match.group(3)
			
			#Formatting the date in auth.log to YYYY-MM-DD format as specified in the question
			dateUF= dateUF + " " + str(yyyy)
			dateStr=datetime.strptime(dateUF, "%b %d %Y")
			date= dateStr.strftime("%Y-%m-%d")

			#Creating a subdictionary for the date, if it DNE already
			if not logDict.get(date):
				logDict[date]={}

			#Creating a subdictionary for the user, if it DNE already
			if not logDict[date].get(user):
				logDict[date][user]={'TOTAL':0, 'IPLIST':{}}
			logDict[date][user]['TOTAL']=logDict[date][user].get('TOTAL')+1

			#Populating the subdictionary with key 'ip' and value 'counter'			
			logDict[date][user]['IPLIST'][ip]=logDict[date][user]['IPLIST'].get(ip,0)+1

		#Logging Reverse Mapping Attempts
		for match in re.finditer(regexRM, line, re.S):
			addrinfo=match.group(2)
			dateUF= line[0:6]
			ip=match.group(3)
			
			#Formatting the date in auth.log to YYYY-MM-DD format as specified in the question
			dateUF= dateUF + " " + str(yyyy)
			dateStr=datetime.strptime(dateUF, "%b %d %Y")
			date= dateStr.strftime("%Y-%m-%d")

			#Creating a subdictionary for the date, if it DNE already
			if not logRevMap.get(date):
				logRevMap[date]={}

			#Creating a subdictionary for the address, if it DNE already
			if not logRevMap[date].get(addrinfo):
				logRevMap[date][addrinfo]={'TOTAL':0, 'IPLIST':{}}
			logRevMap[date][addrinfo]['TOTAL']=logRevMap[date][addrinfo].get('TOTAL')+1

			#Populating the subdictionary with key 'ip' and value 'counter'			
			logRevMap[date][addrinfo]['IPLIST'][ip]=logRevMap[date][addrinfo]['IPLIST'].get(ip,0)+1

#Checking if the optional date parameter has been passed
if logDate is not None:			  
	print("#Failed Password Attempts: ")
	print (json.dumps(logDict[logDate], indent=4, default=str))
	print("#Reverse Mapping Attempts: ")
	print (json.dumps(logRevMap[logDate], indent=4, default=str))

else:
	print("#Failed Password Attempts: ")
	print (json.dumps(logDict, indent=4, default=str))
	print("#Reverse Mapping Attempts: ")
	print (json.dumps(logRevMap, indent=4, default=str))