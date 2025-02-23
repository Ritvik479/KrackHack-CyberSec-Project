from flask import Flask, render_template, request, jsonify
from check_file import file_check, calculate_file_hash  # Import hash-based functions
from scanner_module import scan_file  # Import YARA-based scanning function
import os

app = Flask(__name__)

ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}

def allowed_file(filename):
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"result": "⚠ No file uploaded!"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"result": "⚠ No selected file!"}), 400

    if not allowed_file(file.filename):
        return jsonify({"result": "❌ Invalid file type! Allowed: .exe, .pdf, .docx"}), 400

    # Save the file temporarily to scan with YARA rules
    temp_file_path = os.path.join("uploads", file.filename)
    file.save(temp_file_path)

    # Compute file hash
    file_data = file.read()  # Read file into memory
    file_hash = calculate_file_hash(file_data)

    # Check if hash is in malware database
    is_malicious_hash = file_check(file_hash)

    # Check if file matches YARA rules
    yara_result = scan_file(temp_file_path)

    # Clean up the temporary file
    os.remove(temp_file_path)

    # Determine the overall status based on both checks
    if is_malicious_hash or "Malware detected" in yara_result:
        status = "⚠ Malicious file detected!"
    else:
        status = "✅ File appears safe."

    # Return JSON response with hash and YARA details
    return jsonify({
        "file": file.filename,
        "hash": file_hash,
        "yara_result": yara_result,
        "status": status
    })

if __name__ == "__main__":
    # Ensure the uploads directory exists
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)