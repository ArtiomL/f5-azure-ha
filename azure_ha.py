#!/usr/bin/env python
# f5-azure-ha - F5 High Availability in Microsoft Azure
# https://github.com/ArtiomL/f5-azure-ha
# Artiom Lichtenstein
# v1.0.2, 01/10/2016

import argparse
import atexit
import datetime
import json
import os
import requests
import signal
import socket
import subprocess
import sys
import time

__author__ = 'Artiom Lichtenstein'
__license__ = 'MIT'
__version__ = '1.0.2'

# PID file
strPFile = ''

# Log level to /var/log/ltm (or stdout)
intLogLevel = 0
strLogMethod = 'log'
strLogID = '[-v%s-161001-] %s - ' % (__version__, os.path.basename(sys.argv[0]))

# Logger command
strLogger = 'logger -p local0.'

# Azure RM REST API
class clsAREA(object):
	def __init__(self):
		# Config file
		self.strCFile = '/shared/tmp/scripts/azure/azure_ha.json'
		# Azure RM
		self.strMgmtHost = 'https://management.azure.com/'
		# LBAZ name
		self.strLBName = ''
		# List of route tables to update
		self.lstUDRs = []
		# API version
		self.strAPIVer = '?api-version=2016-03-30'
		# API HTTPS session
		self.objHS = requests.session()
		# Add Content-Type to HTTP headers and modify User-Agent
		self.objHS.headers.update({ 'Content-Type': 'application/json', 'User-Agent': 'f5-azure-ha v%s' % __version__ })

	def funAbsURL(self, strResource):
		return self.strMgmtHost, self.strSubID, self.strRGName, strResource, self.strAPIVer

	def funURI(self, strMidURI):
		return self.strMgmtHost + strMidURI + self.strAPIVer

	def funSwapNICs(self):
		# Use temp (short name) list (lst[0] = nicF5A, lst[1] = nicF5B)
		lst = self.lstF5NICs
		# If old NIC ends with B, reverse the list to replace B with A. Otherwise replace A with B
		if self.strCurNICURI.endswith(lst[1]):
			lst.reverse()
		funLog(2, 'Old NIC: %s, New NIC: %s' % (lst[0], lst[1]))
		return self.funURI(self.strCurNICURI.replace(lst[0], lst[1]))

objAREA = clsAREA()

# Exit codes
class clsExCodes(object):
	def __init__(self):
		self.rip = 6
		self.udr = 5
		self.armAuth = 4

objExCodes = clsExCodes()


def funLog(intMesLevel, strMessage, strSeverity = 'info'):
	if intLogLevel >= intMesLevel:
		if strLogMethod == 'stdout':
			print('%s %s' % (time.strftime('%b %d %X'), strMessage))
		else:
			lstCmd = (strLogger + strSeverity).split(' ')
			lstCmd.append(strLogID + strMessage)
			subprocess.call(lstCmd)


def funARMAuth():
	# Azure RM OAuth2
	global objAREA
	# Read external config file
	if not os.path.isfile(objAREA.strCFile):
		funLog(1, 'Credentials file: %s is missing. (use azure_ad_app.ps1?)' % objAREA.strCFile, 'err')
		return 3

	try:
		# Open the credentials file
		with open(objAREA.strCFile, 'r') as f:
			diCreds = json.load(f)
		# Read and store subscription and resource group
		objAREA.strSubID = diCreds['subID']
		objAREA.strRGName = diCreds['rgName']
		# Read and store F5 VMs' NICs
		objAREA.lstF5NICs = [diCreds['nicF5A'], diCreds['nicF5B']]
		# Current epoch time
		intEpNow = int(time.time())
		# Check if Bearer token exists (in credentials file) and whether it can be reused (expiration with 1 minute time skew)
		if (set(('bearer', 'expiresOn')) <= set(diCreds) and int(diCreds['expiresOn']) - 60 > intEpNow):
			objAREA.objHS.headers.update({ 'Authorization': 'Bearer %s' % diCreds['bearer'].decode('base64') })
			funLog(2, 'Reusing existing Bearer, it expires in %s' % str(datetime.timedelta(seconds=int(diCreds['expiresOn']) - intEpNow)))
			return 0

		# Read additional config parameters
		strTenantID = diCreds['tenantID']
		strAppID = diCreds['appID']
		strPass = diCreds['pass'].decode('base64')
		strEndPt = 'https://login.microsoftonline.com/%s/oauth2/token' % strTenantID
	except Exception as e:
		funLog(1, 'Invalid credentials file: %s' % objAREA.strCFile, 'err')
		funLog(2, repr(e), 'err')
		return 2

	# Generate new Bearer token
	diPayload = { 'grant_type': 'client_credentials', 'client_id': strAppID, 'client_secret': strPass, 'resource': objAREA.strMgmtHost }
	try:
		objHResp = requests.post(url=strEndPt, data=diPayload)
		diAuth = json.loads(objHResp.content)
		if 'access_token' in diAuth.keys():
			# Successfully received new token
			objAREA.objHS.headers.update({ 'Authorization': 'Bearer %s' % diAuth['access_token'] })
			# Write the new token and its expiration epoch into the credentials file
			diCreds['bearer'] = diAuth['access_token'].encode('base64')
			diCreds['expiresOn'] = diAuth['expires_on']
			with open(objAREA.strCFile, 'w') as f:
				f.write(json.dumps(diCreds, sort_keys=True, indent=4, separators=(',', ': ')))
			return 0

	except requests.exceptions.RequestException as e:
		funLog(2, repr(e), 'err')
	return 1


def funRunAuth():
	# Run and check funARMAuth() exit code
	if funARMAuth() != 0:
		funLog(1, 'ARM Auth Error!', 'err')
		sys.exit(objExCodes.armAuth)

	# ARM Auth OK
	funLog(1, 'ARM Auth OK.')
	funLog(3, 'ARM Headers: %s' % str(objAREA.objHS.headers))
	return 0


def funLocIP(strRemIP):
	# Get local private IP
	objUDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# The .connect method doesn't generate any real network traffic for UDP (socket.SOCK_DGRAM)
	objUDP.connect((strRemIP, 1))
	return objUDP.getsockname()[0]


def funGetIPs():
	# Get private IP addresses for F5 NICs
	lstIPs = []
	for i in objAREA.lstF5NICs:
		try:
			# Construct ipconfig URL
			strURL = '%ssubscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces/%s/ipConfigurations/ipconfig1%s' % objAREA.funAbsURL(i)
			# Append private IP to the list
			lstIPs.append(json.loads(objAREA.objHS.get(strURL).content)['properties']['privateIPAddress'])
		except Exception as e:
			funLog(2, repr(e), 'err')
	if len(lstIPs) != 2:
		funLog(2, 'Failed to get both F5 NICs.', 'err')
		return ['undefined']

	strLocIP = funLocIP(lstIPs[0])
	if strLocIP not in lstIPs:
		funLog(2, 'Local machine is not part of the Azure HA pair.', 'err')
		return [strLocIP]

	if strLocIP == lstIPs[1]:
		lstIPs.reverse()
	# Return two strings, local IP first, then peer IP
	funLog(2, 'Local IP: %s, Peer IP: %s' % (lstIPs[0], lstIPs[1]))
	return lstIPs


def funCurState(lstIPs):
	# Get current ARM state for the local machine (lstIPs[0] = local IP, lstIPs[1] = peer IP)
	global objAREA
	funLog(2, 'Current local private IP: %s, Resource Group: %s' % (lstIPs[0], objAREA.strRGName))
	if len(lstIPs) != 2:
		funLog(1, 'Current state: Unknown', 'err')
		return 'Unknown'

	# Construct loadBalancers URL
	strLBURL = '%ssubscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/%s%s' % objAREA.funAbsURL('loadBalancers' + objAREA.strLBName)
	try:
		# Get LBAZ JSON
		objHResp = objAREA.objHS.get(strLBURL)
		# Store the backend pool JSON (for funFailover)
		if objAREA.strLBName:
			# JSON is specific (not an array) since LBAZ name was given
			objAREA.diBEPool = json.loads(objHResp.content)['properties']['backendAddressPools']
		else:
			# JSON is an array of all load balancers (LBAZ name was not given) - use the first one
			objAREA.diBEPool = json.loads(objHResp.content)['value'][0]['properties']['backendAddressPools']
		# Extract backend IP ID ([1:] at the end removes the first "/" char)
		strBEIPURI = objAREA.diBEPool[0]['properties']['backendIPConfigurations'][0]['id'][1:]
		# Store the URI for NIC currently in the backend pool (for funFailover)
		objAREA.strCurNICURI = strBEIPURI.split('/ipConfigurations')[0]
		# Get backend IP JSON
		objHResp = objAREA.objHS.get(objAREA.funURI(strBEIPURI))
		# Extract private IP address
		strARMIP = json.loads(objHResp.content)['properties']['privateIPAddress']
		funLog(2, 'Current private IP in Azure RM (backend pool): %s' % strARMIP)
		if strARMIP == lstIPs[0]:
			# This machine is already Active
			funLog(1, 'Current state: Active')
			return 'Active'

		elif strARMIP == lstIPs[1]:
			# The dead peer is listed as Active - failover required
			funLog(1, 'Current state: Standby')
			return 'Standby'

	except Exception as e:
		funLog(2, repr(e), 'err')
	funLog(1, 'Current state: Unknown', 'warning')
	return 'Unknown'


def funOpStatus(objHResp):
	# Check Azure Async Operation status
	strStatus = 'InProgress'
	# The Azure-AsyncOperation header has the full operation URL
	strOpURL = objHResp.headers['Azure-AsyncOperation']
	funLog(2, 'ARM Async Operation, x-ms-request-id: %s' % objHResp.headers['x-ms-request-id'])
	funLog(3, 'Op URL: %s' % strOpURL)
	funLog(2, 'ARM Async Operation Status: %s' % strStatus)
	while strStatus == 'InProgress':
		try:
			strStatus = json.loads(objAREA.objHS.get(strOpURL).content)['status']
		except Exception as e:
			funLog(2, repr(e), 'err')
			break
	funLog(1, strStatus)
	return strStatus


def funUpdUDR():
	# UDR mode failover (or route table update in LBAZ mode)
	lstIPs = funGetIPs()
	# lstIPs[0] = local IP, lstIPs[1] = peer IP
	if len(lstIPs) != 2:
		funLog(1, 'UDR updates halted.', 'err')
		return 3

	intExCode = 0
	for i in objAREA.lstUDRs:
		# Construct UDR URL
		strURL = '%ssubscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/routeTables/%s%s' % objAREA.funAbsURL(i)
		funLog(1, 'Updating Route Table: %s' % i)
		try:
			# Get UDR JSON
			strUDR = objAREA.objHS.get(strURL).content
			strNewUDR = strUDR.replace(lstIPs[1], lstIPs[0])
			if strNewUDR == strUDR:
				funLog(1, 'No update needed.', 'warning')
				raise Exception('.replace - no matches')
			else:
				objHResp = objAREA.objHS.put(strURL, data = strNewUDR)
				if funOpStatus(objHResp) != 'Succeeded':
					raise Exception('funOpStatus != Succeeded')
		except Exception as e:
			funLog(2, repr(e), 'err')
			intExCode += 1
	return intExCode


def funFailover():
	try:
		strOldNICURL = objAREA.funURI(objAREA.strCurNICURI)
	except AttributeError as e:
		funLog(1, 'No NICs in the Backend Pool!', 'warning')
		funLog(2, repr(e), 'err')
		return 3

	strNewNICURL = objAREA.funSwapNICs()
	try:
		# Get the JSON of the NIC currently in the backend pool
		objHResp = objAREA.objHS.get(strOldNICURL)
		diOldNIC = json.loads(objHResp.content)
		# Remove the LB backend pool from that JSON
		diOldNIC['properties']['ipConfigurations'][0]['properties']['loadBalancerBackendAddressPools'] = []
		# Get the JSON of the new NIC to be added to the backend pool
		objHResp = objAREA.objHS.get(strNewNICURL)
		diNewNIC = json.loads(objHResp.content)
		# Remove the existing backend IP ID from the LB backend pool JSON (stored in funCurState)
		objAREA.diBEPool[0]['properties']['backendIPConfigurations'] = []
		# Add the LB backend pool to the new NIC JSON
		diNewNIC['properties']['ipConfigurations'][0]['properties']['loadBalancerBackendAddressPools'] = objAREA.diBEPool
		# Update the new NIC (add it to the backend pool)
		objHResp = objAREA.objHS.put(strNewNICURL, data = json.dumps(diNewNIC))
		funLog(1, 'Adding the new NIC to LBAZ BE Pool...')
		if funOpStatus(objHResp) != 'Succeeded':
			return 2

		# Update the old NIC (remove it from the backend pool)
		objHResp = objAREA.objHS.put(strOldNICURL, data = json.dumps(diOldNIC))
		funLog(1, 'Removing the old NIC from LBAZ BE Pool... ')
		if funOpStatus(objHResp) == 'Succeeded':
			if objAREA.lstUDRs:
				return funUpdUDR()

			return 0

	except Exception as e:
		funLog(2, repr(e), 'err')
	return 1


def funArgParser():
	objArgParser = argparse.ArgumentParser(
		description = 'F5 High Availability in Microsoft Azure',
		epilog = 'https://github.com/ArtiomL/f5-azure-ha')
	objArgParser.add_argument('-a', help ='test Azure RM authentication and exit', action = 'store_true', dest = 'auth')
	objArgParser.add_argument('-b', help ='Azure LB name (first LB is used if omitted)', dest = 'lbaz')
	objArgParser.add_argument('-c', help ='config file location', dest = 'cfile')
	objArgParser.add_argument('-f', help ='force failover', action = 'store_true', dest = 'fail')
	objArgParser.add_argument('-l', help ='set log level (default: 0)', choices = [0, 1, 2, 3], type = int, dest = 'log')
	objArgParser.add_argument('-r', help ='list of route tables to update', nargs = '+', dest = 'udr')
	objArgParser.add_argument('-s', help ='check current HA state and exit', action = 'store_true', dest = 'state')
	objArgParser.add_argument('-u', help ='UDR mode failover (-r is required)', action = 'store_true', dest = 'umode')
	objArgParser.add_argument('-v', action ='version', version = '%(prog)s v' + __version__)
	objArgParser.add_argument('IP', help = 'peer IP address (required in monitor mode)', nargs = '?')
	objArgParser.add_argument('PORT', help = 'peer HTTPS port (default: 443)', type = int, nargs = '?', default = 443)
	return objArgParser.parse_args()


def main():
	global strLogMethod, intLogLevel, strPFile
	objArgs = funArgParser()

	# If run interactively, stdout is used for log messages
	if sys.stdout.isatty():
		strLogMethod = 'stdout'
		intLogLevel = 1

	# Set log level
	if objArgs.log > 0:
		intLogLevel = objArgs.log

	# Config file location
	if objArgs.cfile:
		objAREA.strCFile = objArgs.cfile

	# Test Azure RM authentication and exit
	if objArgs.auth:
		sys.exit(funRunAuth())


	# Route tables to update
	if objArgs.udr:
		objAREA.lstUDRs = objArgs.udr

	# UDR mode failover
	if objArgs.umode:
		if not objArgs.udr:
			funLog(0, 'No route tables to update in UDR mode! (use -r)', 'err')
			sys.exit(objExCodes.udr)

		funRunAuth()
		sys.exit(funUpdUDR())


	# LBAZ name
	if objArgs.lbaz:
		objAREA.strLBName = '/' + objArgs.lbaz

	if objArgs.state or objArgs.fail:
		# Check current HA state
		funRunAuth()
		if funCurState(funGetIPs()) == 'Standby' and objArgs.fail:
			# Force failover
			sys.exit(funFailover())

		sys.exit()


	# eMonitor mode
	try:
		# Remove IPv6/IPv4 compatibility prefix (LTM passes addresses in IPv6 format)
		strRIP = objArgs.IP.strip(':f')
		# Verify first positional argument is a valid (peer) IP address
		socket.inet_pton(socket.AF_INET, strRIP)
	except (AttributeError, socket.error) as e:
		funLog(0, 'No valid peer IP! (use --help)', 'err')
		funLog(2, repr(e), 'err')
		sys.exit(objExCodes.rip)

	# Verify second positional argument is a valid TCP port, set to 443 if not
	strRPort = str(objArgs.PORT)
	if not 0 < objArgs.PORT <= 65535:
		funLog(1, 'No valid peer TCP port, using 443.', 'warning')
		strRPort = '443'

	# PID file
	strPFile = '_'.join(['/var/run/', os.path.basename(sys.argv[0]), strRIP, strRPort + '.pid'])
	# PID
	strPID = str(os.getpid())

	funLog(2, 'PIDFile: %s, PID: %s' % (strPFile, strPID))

	# Kill the last instance of this monitor if hung
	if os.path.isfile(strPFile):
		try:
			os.kill(int(file(strPFile, 'r').read()), signal.SIGKILL)
			funLog(1, 'Killed the last hung instance of this monitor.', 'warning')
		except OSError:
			pass

	# Record current PID
	file(strPFile, 'w').write(str(os.getpid()))

	# Health monitor
	try:
		objHResp = requests.head(''.join(['https://', strRIP, ':', strRPort]), verify = False)
		if objHResp.status_code == 200:
			os.remove(strPFile)
			# Any standard output stops the script from running. Clean up any temporary files before the standard output operation
			funLog(2, 'Peer: %s is up.' % strRIP)
			print 'UP'
			sys.exit()

	except requests.exceptions.RequestException as e:
		funLog(2, repr(e), 'err')

	# Peer down, ARM action required
	funLog(1, 'Peer down, ARM action required.', 'warning')
	funRunAuth()

	if funCurState([funLocIP(strRIP), strRIP]) == 'Standby':
		funLog(1, 'We\'re Standby in ARM, Active peer down. Trying to failover...', 'warning')
		funFailover()

	sys.exit(1)


@atexit.register
def funExit():
	try:
		os.remove(strPFile)
		funLog(2, 'PIDFile: %s removed on exit.' % strPFile)
	except OSError:
		pass
	funLog(1, 'Exiting...')


if __name__ == '__main__':
	main()
