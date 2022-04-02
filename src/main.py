import os.path
from pathlib import Path
import sys
import yaml
from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog, QTreeWidgetItem, QMessageBox
from PyQt5.QtCore import QObject, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QBrush, QColor
from PyQt5.Qt import QUrl, QDesktopServices
from PyQt5 import QtCore
from qtdesigner_files.ui_interface import Ui_MainWindow
import folder_scanner
import virus_total_api


class VirusTotalWorker(QObject):
    virustotal_sig_done = pyqtSignal(dict)
    # virustotal_sig_failed = pyqtSignal(bool)

    def __init__(self, api_key: str, absolute_file_path: str):
        self.__api_key = api_key
        self.__absolute_file_path = absolute_file_path
        super().__init__()

    @pyqtSlot()
    def submit_scan(self):
        print('Submitting scan to VirusTotal API')
        vt_api = virus_total_api.VTAPI(self.__api_key, self.__absolute_file_path)
        api_response = vt_api.get_result_from_hash()
        if api_response:
            self.virustotal_sig_done.emit(api_response)
        # else:
        #     self.virustotal_sig_failed.emit(False)


class FolderMonitor(QObject):
    new_file_signal = pyqtSignal(dict)

    def __init__(
            self, api_key: str,
            download_folder_path: str,
            exclude_file_extensions: str):
        super().__init__()
        self.__download_folder_path = download_folder_path
        self.__api_key = api_key
        self.exclude_file_extensions = exclude_file_extensions
        self.folder_scanner = None

    @pyqtSlot()
    def run_folder_scan(self):
        while True:
            self.folder_scanner = folder_scanner.FolderScanner(self.__download_folder_path)
            self.folder_scanner.stop_scanning(False)
            self.folder_scanner.add_file_ext_to_ignore_list(self.exclude_file_extensions)
            print('Folder scan Running')
            new_file_path = self.folder_scanner.check_directory_changes()
            if new_file_path:
                file_status = {'file_name': Path(new_file_path).name,
                               'status': 'Scanning',
                               'absolute_file_path': new_file_path}
                self.new_file_signal.emit(file_status)
            else:
                print(f'Stopping Folder Scan')
                break

    def stop_folder_scan(self):
        """Send stop Signal to FolderScanner class"""
        self.folder_scanner.stop_scanning(True)


class Window(QMainWindow):

    def __init__(self):
        super().__init__()
        self.all_files_inside_scan_history_widget = {}
        self.__virustotal_scan_threads = []
        self.__threads = []

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.StopAutoScanBtn.hide()

        self.error_popup = QMessageBox()

        self.ui.ScanHistoryTreeWidget.itemClicked.connect(self.open_link)
        self.setAcceptDrops(True)
        self.init_settings()
        self.ui.VTApiKeyInput.setEchoMode(self.ui.VTApiKeyInput.Password)
        self.ui.FolderLocationBtn.clicked.connect(self.change_folder_directory_handler)
        self.ui.SaveChangesBtn.clicked.connect(self.save_settings)
        self.ui.StartAutoScanBtn.clicked.connect(self.start_autoscan_thread)
        self.ui.StopAutoScanBtn.clicked.connect(self.stop_folder_scan)
        self.ui.ScanHistoryTreeWidget.setColumnWidth(1, 70)
        self.ui.ExclExtensionInput.textEdited.connect(self.reset_save_settings_btn)
        self.ui.VTApiKeyInput.textEdited.connect(self.reset_save_settings_btn)

    def disable_inputs(self):
        self.ui.StartAutoScanBtn.setText('Scan Running')
        self.ui.StartAutoScanBtn.setStyleSheet('color: green')
        self.ui.StopAutoScanBtn.show()
        self.ui.FolderLocationBtn.setDisabled(True)
        self.ui.SaveChangesBtn.setDisabled(True)
        self.ui.VTApiKeyInput.setDisabled(True)
        self.ui.ExclExtensionInput.setDisabled(True)
        self.ui.StartAutoScanBtn.setDisabled(True)

    def enable_inputs(self):
        self.ui.StopAutoScanBtn.hide()
        self.ui.StartAutoScanBtn.setText('Start Autoscan')
        self.ui.StartAutoScanBtn.setStyleSheet('color: black')
        self.ui.FolderLocationBtn.setEnabled(True)
        self.ui.StartAutoScanBtn.setEnabled(True)
        self.ui.SaveChangesBtn.setEnabled(True)
        self.ui.VTApiKeyInput.setEnabled(True)
        self.ui.ExclExtensionInput.setEnabled(True)
        self.ui.StartAutoScanBtn.setEnabled(True)

    def scan_widget_files(self, file_data):
        """Looping through all files inside Qtree Widget
           Spawning thread for each file which need to be scanned"""
        root = self.ui.ScanHistoryTreeWidget.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            if item.text(1) == 'Scanning' or item.text(1) == 'Failed' and item.text(0) == file_data['file_name']:
                virustotal_worker = VirusTotalWorker(self.ui.VTApiKeyInput.text(),
                                                     file_data['absolute_file_path'])
                thread = QThread()
                virustotal_worker.moveToThread(thread)
                self.__virustotal_scan_threads.append((thread, virustotal_worker))
                virustotal_worker.virustotal_sig_done.connect(self.update_widget_item)

                thread.started.connect(virustotal_worker.submit_scan)
                thread.start()

    @pyqtSlot(dict)
    def update_widget_item(self, data: dict):
        """Updating Item inside Qtree Widget"""
        root = self.ui.ScanHistoryTreeWidget.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            if item.text(0) in data.values():
                item.setText(1, data['status'])
                item.setText(2, data['scan_date'])
                item.setText(3, data['detection'])
                item.setText(4, data['permalink'])  # Creating Invisible column in which we store permalink
                for column_id in range(4):
                    item.setToolTip(column_id, 'Click to visit full scan result')
                if int(item.text(3).split('/')[0]) < 1:  # If there's no detection change column color to green else red
                    green_color = QBrush(QColor(125, 255, 102))
                    item.setBackground(3, QColor(green_color))
                else:
                    red_color = QBrush(QColor(252, 71, 71))
                    item.setBackground(3, QColor(red_color))

    def fix_column_length(self):
        """Fix column length when there are > 5 items"""
        self.ui.ScanHistoryTreeWidget.setColumnWidth(3, 84)

    @pyqtSlot(dict)
    def add_item_to_widget(self, file_data: dict):
        item = QTreeWidgetItem([f"{file_data['file_name']}",
                                f"{file_data['status']}"])
        for i in range(4):
            # fix text alignment
            item.setTextAlignment(i, QtCore.Qt.AlignCenter)

        self.ui.ScanHistoryTreeWidget.insertTopLevelItem(0, item)  # insert most recent item at the top
        self.scan_widget_files(file_data)

    def open_link(self):
        """Open link in default web browser"""
        permalink = self.ui.ScanHistoryTreeWidget.currentItem().text(4)
        if permalink is not None:
            url = QUrl(permalink)
            QDesktopServices.openUrl(url)

    def start_autoscan_thread(self):
        if self.valid_setting_parameters():
            self.__threads = []
            folder_monitor_worker = FolderMonitor(self.ui.VTApiKeyInput.text(),
                                                  self.ui.FolderPathLabel.text(),
                                                  self.ui.ExclExtensionInput.text())
            thread = QThread()
            folder_monitor_worker.moveToThread(thread)
            self.__threads.append((thread, folder_monitor_worker))
            folder_monitor_worker.new_file_signal.connect(self.add_item_to_widget)
            thread.started.connect(folder_monitor_worker.run_folder_scan)
            thread.start()
            self.disable_inputs()

    def stop_folder_scan(self):
        for thread, worker in self.__threads:
            worker.stop_folder_scan()
            thread.quit()
            thread.wait()
        self.enable_inputs()

    def init_settings(self):
        """Loading settings from config.yaml"""
        self.load_settings()
        if len(self.ui.ExclExtensionInput.text()) == 0:
            self.ui.ExclExtensionInput.setPlaceholderText('file extensions separated by space: .pdf .doc')

    def change_folder_directory_handler(self):
        """Opening Dialog Window"""
        self.open_dialog_box()

    def reset_save_settings_btn(self):
        if self.ui.SaveChangesBtn.text() == 'Saved':
            self.ui.SaveChangesBtn.setText('Save Changes')
            self.ui.SaveChangesBtn.setStyleSheet('color: Black')
        else:
            print(self.ui.SaveChangesBtn.text())

    def save_settings(self):
        """Save settings into yaml config"""
        vt_api_key = self.ui.VTApiKeyInput.text()
        exclude_file_extensions = self.ui.ExclExtensionInput.text()
        scan_folder_location = self.ui.FolderPathLabel.text()
        try:
            if self.valid_setting_parameters():
                config = {'api_key': vt_api_key,
                          'scan_folder_location': scan_folder_location,
                          'exclude_file_extensions': exclude_file_extensions}
                with open('../config.yaml', 'w') as f:
                    yaml.safe_dump(config, f)
                self.ui.SaveChangesBtn.setText('Saved')
                self.ui.SaveChangesBtn.setStyleSheet('color: green')
        except Exception as e:
            self.error_message(str(e))

    def valid_setting_parameters(self):
        try:
            if len(self.ui.VTApiKeyInput.text()) == 0 or len(self.ui.VTApiKeyInput.text()) < 20:
                raise ValueError('Virustotal Api key is empty')
            if self.check_exclude_file_ext_format(self.ui.ExclExtensionInput.text()):
                self.ui.SaveChangesBtn.setText('Saved')
                self.ui.SaveChangesBtn.setStyleSheet('color: green')
            else:
                raise ValueError('Exclude File extensions must start with . '
                                 'followed by extension and separated by space: .doc .pdf')
            if len(self.ui.FolderPathLabel.text()) == 0:
                raise ValueError('Choose Folder which needs to be scanned')
            return True
        except Exception as e:
            self.error_message(str(e))
            return False

    def error_message(self, e: str):
        """Display error message when trying to save invalid data"""
        self.error_popup.setWindowTitle('Error')
        self.error_popup.setIcon(QMessageBox.Critical)
        self.error_popup.setText(str(e))
        self.error_popup.exec_()

    @staticmethod
    def check_exclude_file_ext_format(file_extensions: str) -> bool:
        """checking if string matches valid extension format"""
        list_of_file_ext = file_extensions.split(' ')
        valid_extensions = 0
        if len(file_extensions) == 0:
            return True
        for file_ext in list_of_file_ext:
            if file_ext.startswith('.') and len(file_ext) > 1:
                valid_extensions += 1
        if len(list_of_file_ext) == valid_extensions:
            return True
        else:
            return False

    def load_settings(self):
        try:
            with open('../config.yaml', 'r') as f:
                config = yaml.safe_load(f.read())
            self.ui.VTApiKeyInput.setText(config['api_key'])
            self.ui.ExclExtensionInput.setText(config['exclude_file_extensions'])
            self.ui.FolderPathLabel.setText(config['scan_folder_location'])
        except Exception as e:
            print(f"Couldn't Load settings from a file: {e}")
            self.error_message(str(e))

    def open_dialog_box(self):
        path = QFileDialog.getExistingDirectory()
        self.ui.FolderPathLabel.setText(path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        file = [u.toLocalFile() for u in event.mimeData().urls()][0]
        self.drop_event_scan(file)

    def drop_event_scan(self, abs_file_path: str):
        valid_parameters = self.valid_setting_parameters()
        if self.valid_drop_event_filesize(abs_file_path):
            if valid_parameters:
                item = {'file_name': Path(abs_file_path).name,
                        'status': 'Scanning',
                        'absolute_file_path': abs_file_path}
                self.add_item_to_widget(item)
        else:
            self.error_message('File size exceeds max File size 32MB')

    def valid_drop_event_filesize(self, abs_file_path):
        file_size = os.stat(abs_file_path).st_size
        valid_file_size = int(f"{file_size / float(1 << 20):,.0f}") <= 32
        if valid_file_size:
            return True
        else:
            return False

if __name__ == '__main__':
    if not os.path.exists('../config.yaml'):
        with open('../config.yaml', 'w') as f:
            conf = {'api_key': '',
                      'exclude_file_extensions': '.tmp .crdownload',
                      'scan_folder_location': r'C:\Users'}
            yaml.safe_dump(conf, f)
    app = QApplication(sys.argv)
    ui = Window()
    ui.show()
    sys.exit(app.exec_())
