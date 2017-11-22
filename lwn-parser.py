import re
import sys
import requests

from bs4 import BeautifulSoup

l = requests.get(sys.argv[1])

soup = BeautifulSoup(l.text, 'html5lib')
tags = soup.select('table[class="OddEven"] > tbody > tr')

# cve id -> i dict
cves = {}

for item in tags[1:]:
    i = {"package": "",
         "date": "",
         "url": ""}
    i["package"] = item("td")[3].text
    i["date"] = item("td")[4].text
    i["url"] = item("a")[0]["href"]
    r = requests.get(i["url"])
    matches = set(re.findall("CVE-\d{4}-\d*", r.text))
    for m in matches:
        if m not in cves.keys():
            cves[m] = i

for cve, data in cves.items():
    r = requests.head("https://security.archlinux.org/"+cve)
    if r.status_code != 200:
        print("{cve} - {package} - {url} - {date}".format(cve=cve, **data))

