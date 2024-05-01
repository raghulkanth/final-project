import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label


class FileScanner(FileSystemEventHandler):
    def __init__(self, malware_signatures, ui):
        super().__init__()
        self.malware_signatures = malware_signatures
        self.ui = ui

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        is_infected = self.scan_file(file_path)
        if is_infected:
            self.ui.update_results(f"Malicious file detected: {file_path}")
            self.delete_file(file_path)

    def scan_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                for signature in self.malware_signatures:
                    if signature in file_content:
                        return True
            return False
        except Exception as e:
            print(f"Error scanning file: {file_path}, {e}")
            return False

    def delete_file(self, file_path):
        try:
            os.remove(file_path)
            print(f"File deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting file: {file_path}, {e}")


class AntivirusUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.results_label = Label(text="Scan results:")
        self.add_widget(self.results_label)

    def update_results(self, result):
        self.results_label.text += f"\n{result}"


class AntivirusApp(App):
    def build(self):
        ui = AntivirusUI()
        folder_to_monitor = r"/storage/emulated/0/Download"
        malware_signatures = [
            b"STANDARD-ANTIVIRUS-TEST-FILE!$H+H",
            b"015fbc0b216d197136df8692b354bf2fc7bd6eb243e73283d861a4dbbb81a751",
            b"This program cannot be run in DOS mode"
        ]
        observer = Observer()
        observer.schedule(FileScanner(malware_signatures, ui), folder_to_monitor, recursive=True)
        observer.start()
        return ui


if __name__ == "__main__":
    AntivirusApp().run()
