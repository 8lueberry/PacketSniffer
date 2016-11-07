#!/usr/bin/python

from __future__ import print_function

import GeoIP
import subprocess as sub
import sys
import re
import urllib2
import os
import gzip
import collections

################################################################################
# Variables
################################################################################
url = 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz'
filename = "GeoLiteCity.dat"
threshold = 10 # how many packet before showing on screen
maxitem = 10 # number of item to remember (large number)
regex = r'IP (.*)\.(.*) > (.*)'
networkAdapter = 'enp4s0' # 'en0'

cache = collections.OrderedDict()

################################################################################
# Download
################################################################################
def download():

    # rename
    if exist(filename):
        os.rename(filename, filename + ".bak")

    # download
    file_name = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(file_name, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print("Downloading: %s Bytes: %s" % (file_name, file_size))
    os.system('cls')
    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8)*(len(status)+1)
        print(status),

    f.close()

    # unzip
    inF = gzip.GzipFile(file_name, 'rb')
    s = inF.read()
    inF.close()

    outF = file(filename, 'wb')
    outF.write(s)
    outF.close()

def exist(filename):
    try:
        f = open(filename)
    except IOError, OSError: # Note OSError is for later versions of python
        return False

    return True

################################################################################
# Print country
################################################################################
def printCountry(ip):
    gir = gi.record_by_addr(ip)

    print(ip)
    if gir is not None:
        print('%s, %s, %s' % (gir['country_name'], gir['region_name'], gir['city']))

    print('%s%s' % ('http://whatismyipaddress.com/ip/', ip))
    print('---------------------------')

################################################################################
# Start sniffing
################################################################################
def sniff():    
    p = sub.Popen(('sudo', 'tcpdump', '-l', '-n', '-t', '-i' + networkAdapter, 'udp'), stdout=sub.PIPE)

    try:
        for row in p.stdout:
            line = row.rstrip()
            match = re.match(regex, line, re.M|re.I)

            if match:
              ip = match.group(1)

              if ip.startswith('192.168.0.'):
                continue

              if not ip in cache:
                cache[ip] = 1

                if len(cache) > maxitem:
                    cache.popitem(False)

              elif cache[ip] == threshold:
                printCountry(ip)
                cache[ip] += 1

              else:
                cache[ip] += 1

    except KeyboardInterrupt:
        p.terminate()            # zombie protection, if needed

if len(sys.argv) > 1:
    if sys.argv[1] == 'update':
        download()

################################################################################
#
################################################################################
gi = GeoIP.open(filename, GeoIP.GEOIP_STANDARD)
sniff()
