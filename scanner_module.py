import yara
import os

# Callback function to handle matches
def mycallback(data):
    if data.get('matches'):
        return yara.CALLBACK_CONTINUE
    return yara.CALLBACK_ABORT  # Stop if no match (optional optimization)

def scan_file(filepath, rules_dir="yara-rules"):
    try:
        # Load all .yar files from the rules directory
        rule_files = {
            f'namespace_{i}': os.path.join(rules_dir, f)
            for i, f in enumerate(os.listdir(rules_dir))
            if f.endswith(".yar")
        }

        if not rule_files:
            return "No YARA rules found."

        # Compile YARA rules
        rules = yara.compile(filepaths=rule_files)

        # Match against the file
        matches = rules.match(filepath, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES)

        if matches:
            return f"Malware detected: {', '.join(m.rule for m in matches)}"
        else:
            return "No malware found."

    except yara.Error as e:
        return f"YARA error: {e}"
    except Exception as e:
        return f"Error: {e}"

# Example usage:
if __name__ == "__main__":
    filepath = "testfile.exe"  # Replace with the uploaded file's path
    print(scan_file(filepath))