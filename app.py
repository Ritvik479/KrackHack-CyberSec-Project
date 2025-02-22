from flask import Flask, render_template, request, flash
import os
from scanner_module import scan_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "supersecretkey"  # For showing messages

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"exe", "zip", "docx"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if "file" not in request.files:
            flash("⚠ No file uploaded!", "danger")
            return render_template("index.html")

        file = request.files["file"]
        if file.filename == "":
            flash("⚠ No selected file!", "warning")
            return render_template("index.html")

        if not allowed_file(file.filename):
            flash("❌ Invalid file type! Only .exe, .zip, .docx allowed.", "danger")
            return render_template("index.html")

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Scan file
        result = scan_file(filepath)
        flash(f"✅ Scan Result: {result}", "success")

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

