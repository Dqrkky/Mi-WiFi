import os
import tarfile
import io

class File:
    def __init__(self, file :str=None):
        self.config = {
            "file": file if file != None and isinstance(file, str) else None,
        }
    def has(
        self,
        attribute :str=None,
        attributeinstance =dict
    ):
        return hasattr(self, attribute) and \
            self.__getattribute__(attribute) != None and \
            isinstance(self.__getattribute__(attribute), attributeinstance)
    def write(self, bytes_ :bytes=None):
        if self.has("config", dict) \
        and "file" in self.config and self.config["file"] != None \
        and bytes_ != None and isinstance(bytes_, bytes):
            with open(
                file=self.config["file"],
                mode="wb+"
            ) as fp:
                fp.write(
                    bytes_
                )
    def read(self):
        if self.has("config", dict) \
        and "file" in self.config and self.config["file"] != None and os.path.exists(self.config["file"]):
            with open(
                file=self.config["file"],
                mode="rb+"
            ) as fp:
                return fp.read()
    def path(self):
        if self.has("config", dict) \
        and "file" in self.config and self.config["file"] != None and os.path.exists(self.config["file"]):
            return os.path.abspath(self.config["file"])

class Zip:
    def __init__(self, name :str=None, bytes_ :bytes=None):
        self.config = {
            "name": name if name != None and isinstance(name, str) else None,
            "bytes": bytes_ if bytes_ != None and isinstance(bytes_, bytes) else None
        }
    def has(
        self,
        attribute :str=None,
        attributeinstance =dict
    ):
        return hasattr(self, attribute) and \
            self.__getattribute__(attribute) != None and \
            isinstance(self.__getattribute__(attribute), attributeinstance)
    def list(self):
        if self.has("config", dict):
            data = None
            if "name" in self.config and self.config["name"] != None:
                data = {
                    "name": self.config["name"],
                    "mode": f'r:{self.config["name"].split(".")[-1]}'
                }
            if "bytes" in self.config and self.config["bytes"] != None:
                data = {
                    "fileobj": io.BytesIO(
                        initial_bytes=self.config["bytes"]
                    ),
                    "mode": "r"
                }
            if data == None and isinstance(data, dict) == False:
                return
            with tarfile.open(
                **data
            ) as fp:
                return [
                    {
                        "name": file.name,
                        "content": fp.extractfile(file).read()
                    } 
                    for file in fp.getmembers() if file.isfile()
                ]