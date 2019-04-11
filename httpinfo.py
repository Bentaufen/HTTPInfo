#!/usr/bin/python

#Ben Taufen
#3/20/2019
#
#This tool is used to fingerprint a website. It should be used during the information gathering
#phase of a web application pentest.
#
#USAGE: requires one argument: full URL
#ex: python httpinfo.py https://netspi.com

import subprocess, os, sys, urlparse

url = urlparse.urlparse(sys.argv[1])
port = str(url.port)
host = str(url.hostname)
path = str(url.path)
scheme = str(url.scheme)

if port == "None":
  if scheme == "https":
    port = 443
  if scheme == "http":
    port = 80
port = str(port)

if path == "":
  path = "/"

print "\nFingerprinting " +  host + ":" + port + path + "...\n"

response = subprocess.check_output("curl -s -D- " + url.geturl(), shell=True)
head = subprocess.check_output("curl -s --head " + url.geturl(),shell=True)

#follow redirections
redirect = True
while redirect:
  redirect = False
  for headers in head.split("\n"):
    if "Location:" in headers:
      location = headers.strip().split(": ")
      response = subprocess.check_output("curl -s -D- " + location[1], shell=True)
      head = subprocess.check_output("curl -s --head " + location[1], shell=True)
      print "Application redirected to " + location[1] + "."
      url = urlparse.urlparse(location[1])
      redirect = True

#nslookup for ip
ns = subprocess.check_output("nslookup " + host, shell=True)
i = 0
address = ""
for line in ns.split("\n"):
  if "Address:" in line:
    if i==1:
      address = line.strip()
    i=i+1
print address

#display webserver (may be inaccurate if server obfuscates)
for headers in head.split("\n"):
  if "server" in headers or "Server" in headers:
    print headers.strip()

###fingerprint web app###
#check headers
for headers in head.split("\n"):
  if "X-Powered-By" in headers or "x-powered-by" in headers:
    xpowerhead = headers.strip().split(": ")
    print "Web Application: " + xpowerhead[1] + ". Found via the X-Powered-By header."
  if "x-redirect-by" in headers or "X-Redirect-By" in headers:
    xredirby = headers.strip().split(": ")
    print "Web Application: " + xredirby[1] + ". Found via the X-Redirect-By header."
  if "x-generator" in headers or "X-Generator" in headers:
    xgen = headers.strip().split(": ")
    print "Web Application: " + xgen[1] + ". Found via the X-Generator header."
  if "wpe-backend" in headers or "WPE-Backend" in headers:
    wpeb = headers.strip().split(": ")
    print "Web Application: " + wpeb[1] + ". Found via the wpe-backend header."

#check cookies
cookies = {"zope3":"Zope","cakephp":"CakePHP","kohanasession":"Kohana","laravel_session":"Laravel","phpbb3_":"phpBB","wp-settings":"WordPress","BITRIX_":"1C-BITRIX","AMP":"AMPcms","django":"Django CMS","DotNetNukeAnonymous":"DonNetNuke","e107_tz":"e107","EPiTrace":"EPiServer","EPiServer":"EPiServer","graffitibot":"Graffiti CMS","hotaru_mobile":"Hotaru CMS","ICMSession":"ImpressCMS","MAKACSESSION":"Indico","InstantCMS":"InstantCMS","CMSPreferredCulture":"Kentico CMS","SN4":"MODx","fe_typo_user":"TYPO3","Dynamicweb":"Dynamicweb","Domain=.wix.com":"Wix","VivvoSessionId":"VIVVO","JSESSIONID":"The Java Platform","ASPSESSIONID":"Microsoft IIS server","ASP.NET_SessionId":"Microsoft ASP.NET","CFID":"Cold Fusion","CFTOKEN":"Cold Fusion","PHPSESSID":"PHP"}
for headers in head.split("\n"):
  if "set-cookie" in headers or "Set-Cookie" in headers:
    cookie = headers.strip().split(": ")
    cookie = cookie[1].split("=")
    if cookie[0] in cookies:
      print "Web application: " + cookies[cookie[0]] + ". Found via cookies."

#check meta tags
for line in response.split("\n"):
  if "name=\"generator\"" in line or "name=\"Generator\"" in line:
    webapp = line.strip().split('"')
    print "Web Application: " + webapp[3] + ". Found via the Generator meta tag."
  if "<body id=\"phpbb\">" in line:
    webapp = line.strip().split('"')
    print "Web Application: phpBB. Found via meta tags."

#brief check of HTML source code - more manual inspection should be done
if "<!-- START headerTags.cfm" in response:
  print "Framework: Adobe ColdFusion. Found via HTML source code."
if "__VIEWSTATE" in response:
  print "Framework: Microsoft ASP.NET. Found via HTML source code."
if "<!-- ZK" in response:
  print "Framework: ZK. Found via HTML source code."
if "ndxz-studio" in response:
  print "Framework: Indexhibit. Found via HTML source code."

#check url
if ".php" in url.geturl():
  print "Web platform: PHP. Found via file extention in URL."
if ".asp" in url.geturl():
  print "Web platform: Microsoft Active Server Pages. Found via file extension in URL."
if ".aspx" in url.geturl():
  print "Web platform: Microsoft ASP.NET. Found via file extension in URL."
if ".jsp" in url.geturl():
  print "Web platform: Java server pages. Found via file extension in URL."
if ".cfm" in url.geturl():
  print "Web platform: Cold Fusion. Found via file extension in URL."
if ".d2w" in url.geturl():
  print "Web platform: WebSphere. Found via file extension in URL."


#robots.txt
robot = subprocess.check_output("curl -s " + url.scheme + "://" + url.netloc + "/robots.txt",shell=True)
if "<html>" not in robot:
  print "robots.txt file found at the URL: " + url.scheme + "://" + url.netloc + "/robots.txt"

#check for XXS-header
if "X-XSS-Protection" not in head and "x-xss-protection" not in head:
    print "WARNING! X-XSS-Protection was not found in the response."

#check for cache control header of no-cache or no-store
if "cache-control" in head or "Cache-Control" in head:
  if "no-store" not in head and "no-cache" not in head:
    print "WARNING! The Cache-Control header is missing either no-cache or no-store."
else:
  print "WARNING! The Cache-Control header was not found in the response."

#check for X-Frame-Options header
if "X-Frame-Options" not in head and "x-frame-options" not in head:
  print "WARNING! The X-Frame-Options header was not found in the response."

#check for HSTS header
if "Strict-Transport-Security" not in head and "strict-transport-security" not in head:
    print "WARNING! HSTS header is missing from the response."
