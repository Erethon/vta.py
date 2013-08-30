## vta.py
vta.py is a simple Python implementation of the VirusTotal public API https://www.virustotal.com/en/documentation/public-api/

I use it to sort my malware samples, so it's lacking a lot of functionalities the full VT API supports. For the time being vta.py can only be used to scan files/urls and get back the results of said scans.

It can be used both as a library in a Python program or as a standalone CLI application. It needs ansicolors([1]) and requests([2]) to work.
 
## Usage as a CLI app
Scanning a url:
<pre>
python vtwrapper.py -u erethon.com
</pre>
or use '' for weird urls
<pre>
python vtwrapper.py -u 'erethon.com/weird-url-!chars' 
</pre>

Scanning a file:
<pre>
python vtwrapper.py -f virus.exe
</pre>

Getting the results for a URL or file that was previously scanned:
<pre>
python vtwrapper.py -r erethon.com
</pre>

for a file use:
<pre>
python vtwrapper.py -F virus.exe
</pre>

## Usage as a library
<pre>
from vta import vtapi

vt = vtapi()
print vt.results("url", "erethon.com")
</pre>

This will print the json response from the server. If you want to 'beautify' it use:
<pre>
vt.print_scam_results(vt.results("url", "erethon.com"))
</pre>

The rest of the fuctions are documented here:
<pre>
vt.sendfile(filename) -- Submits a file to be scanned
vt.results("file","HashOfFile") -- Returns the results of a previously scanned file (you need to use its md5/sha1/sha256 hash)
vt.results("url", "ScannedURL") -- Returns the results of a previously scanned url
vt.scanurl("URL") -- Submits URL to be scanned
</pre>


[1]: https://pypi.python.org/pypi/ansicolors
[2]: https://gist.github.com/kennethreitz/973705
