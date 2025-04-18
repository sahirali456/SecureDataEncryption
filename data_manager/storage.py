import json
import os

class DataManager:
    def __init__(self, filename="secure_data.json"):
        self.filename = filename
        self.data = self._load_data()
    
    def _load_data(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                return json.load(f)
        return {}
    
    def save_data(self, data_id: str, encrypted_text: str, passkey_hash: str):
        self.data[data_id] = {
            "encrypted": encrypted_text,
            "passkey_hash": passkey_hash
        }
        with open(self.filename, "w") as f:
            json.dump(self.data, f)
    
    def get_record(self, data_id: str):
        return self.data.get(data_id)