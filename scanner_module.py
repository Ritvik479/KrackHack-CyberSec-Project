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

