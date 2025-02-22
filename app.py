from flask import Flask, render_template, request, jsonify
from scanner_module import scan_file

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

    # Scan the file using pefile
    result = scan_file(file_data)

    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)