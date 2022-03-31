from typing import List
import os
import time
from os import listdir
from os.path import isfile, join


class FolderScanner:
    ignore_file_extensions = ['.crdownload', '.tmp']  # this needs to be hardcoded
    stop_scan = False
    max_file_size = 32  # MB

    def __init__(self, download_folder_path: str) -> None:
        self.download_folder_path = download_folder_path

    def check_directory_changes(self) -> str:
        print(f"excluded_file_extensions: {self.ignore_file_extensions}")
        files_in_download_directory = self._scan_directory()
        while True and not self.stop_scan:
            time.sleep(2)
            new_scan = self._scan_directory()
            for new_file in new_scan:
                ignored_file = self._check_if_file_in_ignore_list(new_file)
                if not ignored_file and new_file not in files_in_download_directory:
                    file_size = os.stat(f"{self.download_folder_path}\{new_file}").st_size
                    if file_size == 0:
                        print(f'size of file 0')
                        files_in_download_directory.append(new_file)
                    valid_file_size = int(f"{file_size / float(1 << 20):,.0f}") <= self.max_file_size
                    absolute_file_path = self.download_folder_path + '\\' + new_file
                    if '.part' in new_file and valid_file_size:
                        if self._file_downloaded_from_firefox(new_file) and \
                                files_in_download_directory[-1][:3] == new_file[:3]:
                            print(f"found file downloaded from firefox")
                            return self.download_folder_path + '\\' + files_in_download_directory[-1]
                    elif valid_file_size and file_size > 1 and '.part' not in new_file:
                        return absolute_file_path
                    else:
                        print(f"passing", new_file)

    def _scan_directory(self) -> List:
        """Scan directory & return all file names"""
        directory = [f for f in listdir(self.download_folder_path) if
                     isfile(join(self.download_folder_path, f))]
        return directory

    @classmethod
    def stop_scanning(cls, stop: bool) -> None:
        cls.stop_scan = stop

    @classmethod
    def add_file_ext_to_ignore_list(cls, ext: str) -> None:
        file_extensions = ext.split(' ')
        for file_ext in file_extensions:
            if file_ext not in cls.ignore_file_extensions:
                cls.ignore_file_extensions.append(file_ext)

    def _check_if_file_in_ignore_list(self, file_name: str) -> bool:
        for tmp_file_ext in self.ignore_file_extensions:
            if tmp_file_ext in file_name:
                return True
        return False

    def _file_downloaded_from_firefox(self, file_name: str) -> bool:
        """Firefox create temporary file with .part ending when file is not present
         we can assume file was successfully downloaded"""
        abs_file_path = self.download_folder_path + '\\' + file_name
        for _ in range(20):
            # We can assume file is bigger than 32MB if it hasn't been downloaded in 20 sec
            if not os.path.exists(abs_file_path):
                return True
            time.sleep(1)
        return False
