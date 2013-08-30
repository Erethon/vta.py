#Created by Erethon, erethon.com, <info@erethon.com>
#A simple Python implementation of the VirusTotal public API
#https://www.virustotal.com/en/documentation/public-api/
#License is the MIT License, see LICENSE and README.md files for more info
#Copyright (C) 2013 Erethon

import requests
import json
from colors import red, green


class vtapi():
    def __init__(self):
        #self.api = "ASWGFHAHJGASDAGHHKHEGWARJLQGEIQYEQWIUAGHDASD"
        self.api = "INSERT YOUR VIRUS TOTAL PUBLIC API HERE"
        self.baseurl = "https://www.virustotal.com/vtapi/v2/"

    #Print results from a file/url
    def print_scan_results(self, results):
        if results['response_code'] == 0:
            print "Url not found, or scanned yet. Try again later"
        else:
            print ("""Permalink: %s \nScandate: %s \n"""
                   % (results['permalink'], results['scan_date']))
        for i in results['scans']:
            print("%s: " % i),
            if (str(results['scans'][i]['detected']) == "False"):
                    print green("Clean")
            else:
                    print (red("Malicious -- %s"
                           % str(results['scans'][i]['result'])))

    #Print reply for a url scan request
    def print_url_scan(self, results):
        print ("""Permalink: %s \nURL: %s \nDate: %s \nID: %s"""
               % (results['permalink'], results['resource'],
                  results['scan_date'], results['scan_id']))

    #Print reply for a file scan request
    def print_file_scan(self, results):
        print results['verbose_msg']
        print "Permalink: %s" % results['permalink']

    #Checking if any `networking` related errors occured
    def check_results(self, r):
        try:
            results = r.json()
        except ValueError:
            print "URL not found, malformed URL or invalid API token"
            exit(1)
        return results

    #Function to get results of a scanned file/url
    def results(self, mode, resource):
        url = self.baseurl + "%s/report" % mode
        values = {"resource": resource,
                  "apikey": self.api}

        r = requests.post(url, values)
        results = self.check_results(r)
        return results

    #Scan a url
    def scanurl(self, resource):
        url = self.baseurl + "url/scan"
        values = {"url": resource,
                  "apikey": self.api}

        r = requests.post(url, values)
        results = self.check_results(r)
        return results

    #Scan a file
    def sendfile(self, filename):
        url = self.baseurl + "file/scan"
        try:
            f = open(filename, "rb")
        except:
            print "Could not open file"

        files = {"file": f}
        values = {"apikey": self.api}
        r = requests.post(url, values, files=files)
        results = self.check_results(r)
        return results
