#Created by Erethon, erethon.com, <info@erethon.com>
#A simple Python implementation of the VirusTotal public API
#https://www.virustotal.com/en/documentation/public-api/
#License is the MIT License, see LICENSE and README.md files for more info
#Copyright (C) 2013 Erethon

from vta import vtapi
import argparse
import hashlib


def parse_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url",
                        help="URL to scan")
    parser.add_argument("-F", "--results-file", dest="sfile",
                        help="Get report of previously scanned file. If the "
                        "given filename cannot be found/opened, we'll assume "
                        "it's a hash.")
    parser.add_argument("-U", "--results", dest="url_res",
                        help="Get report of previously scanned url")
    parser.add_argument("-f", "--file", dest="file",
                        help="Scan file")
    parser.add_argument("-v", "--verbose", default=False, action="store_true",
                        dest="verbose", help="Print complete reply")
    return parser.parse_args()


def main():
    arg = parse_options()
    vt = vtapi(arg.verbose)

    #Scan url
    if arg.url:
        vt.print_url_scan(vt.scanurl(arg.url))

    #Get results of file
    elif arg.sfile:
        try:
            f = open(arg.sfile, "r")
            fhash = hashlib.sha256()
            fhash.update(str(f.read()))
            value = fhash.hexdigest()
        except:
            value = arg.sfile
        vt.print_scan_results(vt.results("file", value))

    #Get results of url
    elif arg.url_res:
        vt.print_scan_results(vt.results("url", arg.url_res))

    #Send file for scan
    elif arg.file:
        vt.print_file_scan(vt.sendfile(arg.file))


if __name__ == "__main__":
    exit(main())
