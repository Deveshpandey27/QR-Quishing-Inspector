from flask import Flask, render_template, request
import os
from utils.qr_decoder import decode_qr

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

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    decoded_data = decode_qr(file_path)
    if decoded_data:
        return f"Decoded QR Code:<br><br>{decoded_data}"

    return "No QR code found in the uploaded image."


if __name__ == "__main__":
    app.run(debug=True)