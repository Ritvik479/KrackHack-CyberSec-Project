from flask import Flask, render_template, request, jsonify
import hashlib
from check_file import file_check, calculate_file_hash  # Import only file_check function

app = Flask(__name__)

ALLOWED_EXTENSIONS = {"exe", "pdf", "docx"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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

    file_data = file.read()  # Read file into memory

    # Compute file hash
    file_hash = calculate_file_hash(file_data)

    # Check if hash is in malware database
    is_malicious = file_check(file_hash)

    # Return JSON response with hash details
    return jsonify({
        "file": file.filename,
        "hash": file_hash,
        "status": "⚠ Malicious file detected!" if is_malicious else "✅ File appears safe."
    })

if __name__ == "__main__":
    app.run(debug=True)