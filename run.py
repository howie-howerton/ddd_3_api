'''
Reference:  https://docs.python.org/2/library/xml.etree.elementtree.html#elementtree-xpath

Dependencies:  DDD_3.0_API module - The DDD_3.0_API.py module needs to be placed in the same directory as this script.

Reminder:  Use the config.ini file to specify your api_key, ddd_ip and output_csv variable values.  The
           client_uuid variable should be globally unique (read: It needs to be different for each endpoint upon
           which you run the script.  If you delete the client_uuid line, a client_uuid will automatically be
           generated by the script (and added to the local config.ini file).

'''
import xml.etree.ElementTree as ET
import csv, uuid, hashlib, os, datetime, json
from ConfigParser import SafeConfigParser
from DDD_3_0_API import Client
from pprint import pprint


def get_or_create_client_uuid():
    '''Retrieve or Create the client's UUID'''
    parser = SafeConfigParser()
    parser.read('config.ini')
    if parser.has_option('input', 'client_uuid'):
        client_uuid = parser.get('input', 'client_uuid')
    else:
        client_uuid = str(uuid.uuid4())
        parser.set('input', 'client_uuid', client_uuid)
        cfgfile = open('config.ini', 'w')
        parser.write(cfgfile)
        cfgfile.close()
    return client_uuid

def hash_file(filename):
    '''Calculate the SHA1 of a file'''
    h = hashlib.sha1()
    with open(filename,'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()

def hash_url(url):
    '''Calculate the SHA1 of a URL'''
    h = hashlib.sha1()
    h.update(url)
    return h.hexdigest()


def process_list_of_dict(list_of_dict):
    '''This function searches through the list_of_dict list and ensures that each MD5 and its corresponding SHA1
    are only output once (no duplicates).  The MD5s and SHA1s are output to the console as well as to a CSV file.'''
    unique_md5s = []
    csvfile = open(output_csv, 'wb')
    try:
        w = csv.writer(csvfile)
        w.writerow(('MD5', 'SHA1'))
        for i in list_of_dict:
            if i['FilterCRC']:
                if i['DataMD5'] not in unique_md5s:
                    unique_md5s.append(i['DataMD5'])
                    print "MD5: {0}   SHA1: {1}".format(i['DataMD5'], i['SourceFileSHA1'])
                    w.writerow((i['DataMD5'], i['SourceFileSHA1']))
    finally:
        csvfile.close()

def update_last_query_id(list_of_dict):
    '''This function searches through the list_of_dict list in order to find the last_query_id (ie: the largest id
    value in the list.  The value is output to the screen and also written to the config.ini file.'''
    global last_query_id
    for i in list_of_dict:
        if i['ID'] > last_query_id:
            last_query_id = i['ID']
    print "LastQueryID: {0}".format(last_query_id)
    parser = SafeConfigParser()
    parser.read('config.ini')
    parser.set('tracker', 'last_query_id', str(last_query_id))
    cfgfile = open('config.ini', 'w')
    parser.write(cfgfile)
    cfgfile.close()

if __name__ == '__main__':
    #First, read in the variables from the config.ini file
    try:
        parser = SafeConfigParser()
        parser.read('config.ini')
        api_key = parser.get('input', 'api_key')
        ddd_ip = parser.get('input', 'ddd_ip')
        output_csv = parser.get('input', 'output_csv')
        client_uuid = get_or_create_client_uuid()
        last_query_id = parser.get('tracker', 'last_query_id')
    except:
        print "Error reading 'config.ini' config file. Please ensure that this file is in the same directory as the script."
        exit(0)

    # Create an DDD_3_0_API.Client that we'll use to talk to the API
    c = Client(api_key, ddd_ip, client_uuid, disable_cert_checking=True)
    print "************* variables read in from the script's config.ini file **************"
    print "API Key:         {0}".format(c.api_key)
    print "DDD IP:     {0}".format(c.ddd_ip)
    print "CSV Output:      {0}".format(output_csv)
    print "Client UUID:     {0}".format(client_uuid)
    print "last_query_id:   {0}".format(last_query_id)
    print "*" * 80
    try:
        # Register this python client to the DDD
        print "[+] Registering with DDD..."
        r = c.register()
        print "Response Status Code: {0}\n".format(r.status_code)
        # Test the connection to the DDD
        print "[+] Testing the connection with DDD..."
        r = c.test_connection()
        print "Response Status Code: {0}\n".format(r.status_code)
        # Retrieve the blacklists - 'blacklist_items is a unicode string of XML'
        '''Note: If you want to retrieve ALL blacklist items every time, set last_query_id=0.  If you only want to
        return NEW items that haven't been fetched previously, set last_query_id=last_query_id (which will allow
        the script to fetch the last_query_id value from the config.ini file.  This file is updated with the
        last_query_id upon each running of the script'''
        print "[+] Retrieving blacklist..."
        r = c.get_black_lists(last_query_id="0")  # Use 'last_query_id="0"' if you want ALL items.
        print "Response Status Code: {0}\n".format(r.status_code)
        if r.status_code == 419:
            print "You must call .register() before issuing any other web api calls."
        if r.status_code == 421:
            print "No blacklist information was available."
        blacklist_items = r.text
        print r.status_code
        print r.text                  
    except Exception as e:
        print "Error making web call to DDD.  The raw exception message was:\n{0}".format(e)
        exit(1)
    #list_of_dict = convert_blacklist_xml_string_to_list_of_dict(blacklist_items)
    print type(blacklist_items)
    response_dict = json.loads(blacklist_items)
    print type(response_dict)
    pprint(response_dict)
    process_list_of_dict(response_dict['data']['REPORTS'])
    update_last_query_id(response_dict['data']['REPORTS'])

#TODO: Add logging
#TODO: Add a def to interpret the HTTP status_code responses

'''
interval_start = datetime.datetime.now() - datetime.timedelta(minutes=30) # Thirty Minutes Ago
interval_end = datetime.datetime.now()  # Now
'''