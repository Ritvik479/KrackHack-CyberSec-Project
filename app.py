from flask import Flask, render_template, request, jsonify
import os
from scanner_module import scan_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "supersecretkey"  # For showing messages

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"exe", "docx", "pdf", "txt"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

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
        return jsonify({"result": "❌ Invalid file type! Allowed: .exe, .zip, .docx"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    # Scan file
    result = scan_file(filepath)
    return jsonify({"result": f"✅ Scan Result: {result}"})

if __name__ == "__main__":
    app.run(debug=True)

