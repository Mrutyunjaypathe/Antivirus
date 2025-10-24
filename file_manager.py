import os
import tempfile

class FileManager:
    @staticmethod
    def delete_file(file_path):
        try:
            os.remove(file_path)
            return True, f"File deleted: {os.path.basename(file_path)}"
        except Exception as e:
            return False, f"Failed to delete: {e}"
    
    @staticmethod
    def clean_temp_files():
        temp_dirs = []
        cleaned_files = 0
        
        if os.name == 'nt':
            temp_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                'C:\\Windows\\Temp'
            ]
        else:
            temp_dirs = ['/tmp', '/var/tmp']
            
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                try:
                    for file in os.listdir(temp_dir):
                        file_path = os.path.join(temp_dir, file)
                        if os.path.isfile(file_path) and file.endswith('.tmp'):
                            try:
                                os.remove(file_path)
                                cleaned_files += 1
                            except:
                                continue
                except:
                    continue
                    
        return cleaned_files
    
    @staticmethod
    def get_quick_scan_locations():
        locations = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            "C:\\Windows\\Temp" if os.name == 'nt' else "/tmp"
        ]
        return [loc for loc in locations if os.path.exists(loc)]