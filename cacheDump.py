import os
import tarfile

class File:
    def __init__(self, file :str=None):
        self.config = {
            "file": file if file != None and isinstance(file, str) else None,
        }
    def write(self, bytes_ :bytes=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and bytes_ != None and isinstance(bytes_, bytes):
            with open(
                file=self.config["file"],
                mode="wb+"
            ) as fp:
                fp.write(
                    bytes_
                )
    def read(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and os.path.exists(self.config["file"]):
            with open(
                file=self.config["file"],
                mode="rb+"
            ) as fp:
                return fp.read()
    def path(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and os.path.exists(self.config["file"]):
            return os.path.abspath(self.config["file"])

class Zip:
    def __init__(self, file :str=None):
        self.config = {
            "file": file if file != None and isinstance(file, str) else None,
        }
    def list(self):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and os.path.exists(self.config["file"]):
            with tarfile.open(
                name=self.config["file"],
                mode=f'r:{self.config["file"].split(".")[-1]}'
            ) as fp:
                return fp.list()