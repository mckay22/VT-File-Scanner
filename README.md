# VT-File-Scanner


# General Info
Simple File Scanner capable of scanning Download Folder location & drag & drop files, and automatically send files for scan to Virustotal

# Requirements
```
Windows 10
Python~=3.9
PyQt5~=5.15.6
requests~=2.27.1
```

# Setup

To run this project:
* Register on https://www.virustotal.com & retrieve your personal Api Key
```clone repository
git clone https://github.com/mckay22/VT-File-Scanner
cd VT-File-Scanner
pip3 install -r requirements.txt
python main.py
```

# Usage

https://user-images.githubusercontent.com/98211187/161104491-b2de0522-d93c-41f6-af14-458236025486.mp4

* Drag & Drop Any file which is < 32 MB
* For Auto scan feature you need to choose your browser Default Download Location
* Exclude File Extensions field is to filter out sensitive files which shouldn't  be scanned like .doc, .pdf separated by white space


# Limits
Virustotal Api is storing all scans based on sha256 of a File. If you upload or scan File which is not in Virustotal DB scan might take from 2 up to 10 minutes.
Everyone should follow Virustotal quota limits otherwise, api key might get revoked.
```
Request rate 	4 lookups / min
Daily quota 	500 lookups / day
Monthly quota 	15.50 K lookups / month
```

# TODO
* rework QtDesigner with proper layouts
* add logging
* write tests
* Linux support
* Add Popup Window when newly downloaded file is scanned
* Add confidence level based on AV detection