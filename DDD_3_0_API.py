'''
This python module was created to facilitate 3rd party integration with Trend Micro Deep Discovery Director.

Dependencies:    This module imports the popular 3rd party "requests" module which is used to the handle
                 HTTP(S) communications of the Client class.
                 
Usage:           

import DDD_3.0_API
# Create a Client instance
c = Client(api_key, ddd_ip, client_uuid, disable_cert_checking=True)
# Test the client connection with DDD
c.test_connection()
# Get the Suspicious Object/Blacklist
c.get_black_lists(last_query_id=0) 
# Use the same process for other available methods
c.<other_methods_here>

All web methods will return a Requests response object (http://docs.python-requests.org/en/master/api/#requests.Response).
The most common attributes of the response object are:

content - Content of the response, in bytes.
status_code - Integer Code of responded HTTP Status, e.g. 404 or 200.
text - Content of the response, in unicode.

For example:

response = c.get_black_lists(last_query_id=0)
blacklist_xml = response.text 
# Note: get_black_lists returns data as an XML string.

                 
'''

import time, hashlib, uuid, platform, re, os, socket, datetime
import requests

class Client():
    '''A client object for interacting with DDD's API.'''

    def __init__(self, api_key, ddd_ip, client_uuid, disable_cert_checking=True):
        '''Initialize the client connection to the DDD's API.'''
        if not ((type(api_key) == str) and (re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', api_key))):
            raise ValueError("Client __init__ parameter 'api_key' must be a STRING with valid API key format")
        if not ((type(ddd_ip) == str) and ((self.is_valid_ip(ddd_ip)) or (self.is_valid_hostname(
            ddd_ip)))):
            raise ValueError("Client __init__ parameter 'ddd_ip' must be a STRING that contains a valid IP address or hostname.") 
        if not ((type(client_uuid) == str) and (re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',client_uuid))):
            raise ValueError("Client __init__ parameter 'client_uuid' must be a STRING that contains a valid UUID - ie: str(uuid.uuid4()) ")  
        if not (type(disable_cert_checking) == bool):
            raise ValueError("Client __init__ parameter 'disable_cert_checking' must be a BOOL that is either True or False")        
        self.api_key = api_key #Note: This should be the API key from the RDQA page.  NOT the API key from the help page.
        self.ddd_ip = ddd_ip
        self.protocol_version = "1.0"   
        self.product_name = "DDD"
        self.client_hostname = self.get_system_hostname()
        self.client_uuid = client_uuid
        self.source_id = "1"            # source_id of 1 == User submission
        self.source_name = "Python API Client" 
        self.use_checksum_calculating_order = True
        if disable_cert_checking == True:
            requests.packages.urllib3.disable_warnings() # To disable warning for Self-Signed Certificates
        self.register()

    def calculate_checksum(self, headers):
        '''Calculate the header checksum used for authentication.'''
        #TODO: Extend method to handle use_checksum_calculating_order property == False
        if self.use_checksum_calculating_order == True:
            x_ddd_checksumcalculatingorder_list = headers['X-DDD-ChecksumCalculatingOrder'].split(",")
            x_ddd_checksumcalculatingorder = ""
            for i in x_ddd_checksumcalculatingorder_list:
                x_ddd_checksumcalculatingorder += headers[i]
            x_ddd_checksum = hashlib.sha1(self.api_key + x_ddd_checksumcalculatingorder).hexdigest()
            return x_ddd_checksum

    def calculate_checksum2(self, headers, data):
        '''Calculate the header checksum used for authentication (headers + body).'''
        #TODO: Extend method to handle use_checksum_calculating_order property == False
        if self.use_checksum_calculating_order == True:
            x_ddd_checksumcalculatingorder_list = headers['X-DDD-ChecksumCalculatingOrder'].split(",")
            x_ddd_checksumcalculatingorder = ""
            for i in x_ddd_checksumcalculatingorder_list:
                x_ddd_checksumcalculatingorder += headers[i]
            x_ddd_checksum = hashlib.sha1(self.api_key + x_ddd_checksumcalculatingorder + data).hexdigest()
            return x_ddd_checksum

    def get_challenge(self):
        '''Get the unique challenge UUID value for the Challenge header.'''
        challenge = str(uuid.uuid4())
        return challenge

    def get_epoch_time(self):
        '''Get the epoch time (for the X-DDD-Time header value.'''
        epoch_time = str(int(time.time()))
        return epoch_time

    def get_epoch_from_datetime(self, dt):
        '''Calculate epoch time from a datatime object'''
        epoch_format = str(int(time.mktime(dt.timetuple())))
        return epoch_format

    def get_system_hostname(self):
        '''Get the hostname of the system from which the script is being run'''
        hostname = platform.node()
        return hostname
    
    def hash_file(self, filename):
        '''Calculate the SHA1 of a file'''
        h = hashlib.sha1()
        with open(filename,'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
        return h.hexdigest()    

    def hash_url(self, url):
        '''Calculate the SHA1 of a URL'''
        h = hashlib.sha1()
        h.update(url)
        return h.hexdigest()

    def is_valid_url(self, url):
        import re
        regex = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d{1,5})?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if url is not None and regex.search(url):
            return True
        else:
            return False

    def is_valid_ip(self, address):
        try: 
            socket.inet_aton(address)
            return True
        except:
            return False    

    def is_valid_hostname(self, hostname):
        # TODO: Make a better regex
        if re.match("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", hostname):
            return True
        else:
            return False  

    def test_connection(self):
        '''Issue a request to make sure that all settings are correct and the connection to DDD's API is good.'''
        url = "https://{ddd_ip}/web_service/{service}".format(ddd_ip=self.ddd_ip,
                                                                                 service="test_connection")
        headers = {
            "X-DDD-ProtocolVersion": self.protocol_version,
            "X-DDD-Time": self.get_epoch_time(),
            "X-DDD-Challenge": self.get_challenge(),
            "X-DDD-ChecksumCalculatingOrder": "X-DDD-ProtocolVersion,X-DDD-Time,X-DDD-Challenge"
        }
        # Calculate the header checksum and add it to the list of headers
        headers["X-DDD-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def register(self):
        '''Send a registration request to register or update registration information on ddd.'''
        url = "https://{ddd_ip}/web_service/{service}".format(ddd_ip=self.ddd_ip,
                                                                                 service="register")
        headers = {
            "X-DDD-ProtocolVersion": self.protocol_version,
            "X-DDD-ProductName": self.product_name,
            "X-DDD-ClientHostname": self.client_hostname,
            "X-DDD-ClientUUID": self.client_uuid,
            "X-DDD-SourceID": self.source_id,
            "X-DDD-SourceName": self.source_name,
            "X-DDD-Time": self.get_epoch_time(),
            "X-DDD-Challenge": self.get_challenge(),
            "X-DDD-ChecksumCalculatingOrder": "X-DDD-ProtocolVersion,X-DDD-ProductName,X-DDD-ClientHostname,"
                                               "X-DDD-ClientUUID,X-DDD-SourceID,X-DDD-SourceName,X-DDD-Time,"
                                               "X-DDD-Challenge",
            "X-DDD-Checksum": ""
        }
        #Calculate the header checksum and add it to the list of headers
        headers["X-DDD-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def unregister(self):
        '''Send an unregister request to remove client registration information from DDD.'''
        url = "https://{ddd_ip}/web_service/{service}".format(ddd_ip=self.ddd_ip,
                                                                                 service="unregister")
        headers = {
            "X-DDD-ProtocolVersion": self.protocol_version,
            "X-DDD-ClientUUID": self.client_uuid,
            "X-DDD-Time": self.get_epoch_time(),
            "X-DDD-Challenge": self.get_challenge(),
            "X-DDD-ChecksumCalculatingOrder": "X-DDD-ProtocolVersion,X-DDD-ClientUUID,X-DDD-Time,X-DDD-Challenge",
			"X-DDD-Checksum": ""
        }
        #Calculate the header checksum and add it to the list of headers
        headers["X-DDD-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def get_black_lists(self, last_query_id=0):
        '''Issue a request to retrieve all blacklist information'''
        if not ((type(last_query_id) == str) and (last_query_id.isdigit())):
            raise ValueError("get_blacklists parameter 'last_query_id' must be a STRING with a value that's greater than '0'")
        url = "https://{ddd_ip}/web_service/{service}".format(ddd_ip=self.ddd_ip,
                                                                                 service="get_black_lists")
        headers = {
            "X-DDD-ProtocolVersion": self.protocol_version,
            "X-DDD-ClientUUID": self.client_uuid,
            "X-DDD-Time": self.get_epoch_time(),
            "X-DDD-Challenge": self.get_challenge(),
            "X-DDD-ChecksumCalculatingOrder": "X-DDD-ProtocolVersion,X-DDD-ClientUUID,X-DDD-LastQueryID,"
                                               "X-DDD-Time,X-DDD-Challenge"
        }
        # Add the X-DDD-LastQueryID header (default is "0")
        headers["X-DDD-LastQueryID"] = str(last_query_id)
        # Calculate the header checksum and add it to the list of headers
        headers["X-DDD-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r
