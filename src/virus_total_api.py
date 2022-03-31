import json
import pathlib
from typing import Dict
import time
import hashlib
import requests


class VTAPI:
    api_file_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    api_file_scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    def __init__(self, api_key: str, abs_file_path: str) -> None:
        self.api_key = api_key
        self.abs_file_path = abs_file_path
        self.file_name = self.get_filename()
        self.file_hash = self.calculate_file_hash()

    def get_filename(self) -> str:
        file_name = pathlib.Path(self.abs_file_path).name
        return file_name

    def get_result_from_hash(self) -> Dict or None:
        """First We try to receive the latest possible scan, If there's none we have to wait considerable amount of time
        till virustotal scan the file"""
        file_uploaded = False
        print(f"getting result from sha256")
        for _ in range(10):
            params = {'apikey': self.api_key, 'resource': self.file_hash}
            r = requests.get(self.api_file_report_url, params=params)
            if r.status_code == 200:
                if int(r.json()['response_code']) == 1:
                    response = self.parse_response(json.loads(r.content))
                    return response
                elif int(r.json()['response_code']) == 0 and not file_uploaded:
                    self.upload_file()
                    file_uploaded = True
                elif int(r.json()['response_code']) == -2:
                    time.sleep(30)
                    print(f"File is queued for analysis")
                else:
                    time.sleep(
                        15)  # we need to wait between requests because analyzing of forced scan might take up to 1 min
            else:
                time.sleep(15)
        return

    def calculate_file_hash(self) -> hashlib.sha256():
        """calculating file hash"""
        print(f"ABS {self.abs_file_path}")
        with open(self.abs_file_path, 'rb') as f:
            readable_hash = hashlib.sha256(f.read()).hexdigest()
        return readable_hash

    def upload_file(self) -> None:
        print(f"Uploading file")
        params = {'apikey': self.api_key}
        read_file = open(self.abs_file_path, 'rb')
        files = {'file': (self.file_name, read_file)}
        r = requests.post(self.api_file_scan_url, files=files, params=params)
        read_file.close()
        if r.status_code != 200:
            raise ValueError('Error occured when uploading file', r.content, r.status_code)

    def parse_response(self, response: Dict) -> Dict:
        parsed_report = {
            'file_name': self.file_name,
            'status': 'Success',
            'scan_date': response['scan_date'],
            'permalink': response['permalink'],
            'detection': f"{response['positives']}/{response['total']}"}
        return parsed_report
