# VT-File-Scanner


#General Info
Simple File Scanner capable of scanning Download Folder location, and automatically send files for scan to Virustotal

#Requirements
```
Windows 10 +
Python~=3.9
PyYAML~=6.0
PyQt5~=5.15.6
requests~=2.27.1
```

#Setup

To run this project:
* Register on https://www.virustotal.com & retrieve your personal Api Key
```clone repository
git clone https://github.com/mckay22/VT-File-Scanner
cd VT-File-Scanner
pip3 install -r requirements.txt
python src/ui.py
```

#Usage
<video width="320" height="240" controls>
  <source src="usage_vid.mp4" type="video/mp4">
</video>

* Drag & Drop Any files which are < 32 MB
* For Auto scan feature you need to choose your browser Default Download Location
* Exclude File Extensions field is to filter out sensitive files which shouldn't  be scanned like .doc, .pdf separated by white space


#Limits
Virustotal API need sha256 of a File to check if it was previously scanned. If sha256 is unique it can take from 2 up to 10 minutes to get response from Virsutotal Api.
Everyone should follow Virustotal quota allowances otherwise, api key might get revoked.
```
Request rate 	4 lookups / min
Daily quota 	500 lookups / day
Monthly quota 	15.50 K lookups / month
```

#TODO
* rework QtDesigner with proper layouts
* add logging
* write tests
* Linux support
