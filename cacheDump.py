import os

class Cache:
    def __init__(self, file :str=None, encoding :str="utf-8"):
        self.config = {
            "file": file if os.path.exists(file) else None,
            "encoding": encoding if encoding != None and isinstance(encoding, str) else None
        }
    def write(self, bytes_ :bytes=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and isinstance(self.config["file"], str) and "encoding" in self.config and self.config["encoding"] != None and isinstance(self.config["encoding"], str) and bytes_ != None and isinstance(bytes_, bytes):
            with open(
                file=self.config["file"],
                mode="wb+",
                encoding=self.config["encoding"]
            ) as fp:
                fp.write(
                    bytes_
                )
    def write(self, bytes_ :bytes=None):
        if hasattr(self, "config") and self.config != None and isinstance(self.config, dict) and "file" in self.config and self.config["file"] != None and isinstance(self.config["file"], str) and "encoding" in self.config and self.config["encoding"] != None and isinstance(self.config["encoding"], str):
            with open(
                file=self.config["file"],
                mode="rb+",
                encoding=self.config["encoding"]
            ) as fp:
                return fp.read()