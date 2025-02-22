'''
import yara

RULES_PATH = "rules.yar"

def scan_file(filepath):
    try:
        rules = yara.compile(RULES_PATH)
        matches = rules.match(filepath)
        if matches:
            return f"Malware detected: {matches}"
        else:
            return "No malware found."
    except Exception as e:
        return f"Error: {e}"
'''

import pefile

def scan_file(file_data):
    try:
        pe = pefile.PE(data=file_data)  # Load file from memory

        # Extract relevant PE information
        scan_result = {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [sec.Name.decode().strip() for sec in pe.sections],
            "num_of_sections": len(pe.sections),
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        }

        return scan_result  # Return dictionary with scan results

    except pefile.PEFormatError:
        return "Invalid PE file!"