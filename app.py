from flask import Flask, render_template, request
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():

    if "qr_image" not in request.files:
        return "No file selected."

    file = request.files["qr_image"]

    if file.filename == "":
        return "No file selected."

    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))

    return "QR Code uploaded successfully!"


if __name__ == "__main__":
    app.run(debug=True)