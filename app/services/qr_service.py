import io
import cv2
import numpy as np

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False


def decode_qr_image(image_bytes: bytes) -> dict:
    if not image_bytes:
        return {"success": False, "error": "Empty file received."}

    np_arr = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if image is None:
        return {
            "success": False,
            "error": "Could not decode image. Please ensure the file is a valid PNG, JPG, WEBP, or BMP."
        }

    detector = cv2.QRCodeDetector()

    data, bbox, _ = detector.detectAndDecode(image)
    if data and data.strip():
        return {"success": True, "data": data.strip(), "method": "opencv_standard"}

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    data, bbox, _ = detector.detectAndDecode(gray)
    if data and data.strip():
        return {"success": True, "data": data.strip(), "method": "opencv_grayscale"}

    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    thresh = cv2.adaptiveThreshold(
        blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    data, bbox, _ = detector.detectAndDecode(thresh)
    if data and data.strip():
        return {"success": True, "data": data.strip(), "method": "opencv_adaptive_thresh"}

    if PYZBAR_AVAILABLE:
        try:
            barcodes = pyzbar_decode(gray)
            for barcode in barcodes:
                text = barcode.data.decode("utf-8", errors="ignore").strip()
                if text:
                    return {"success": True, "data": text, "method": "pyzbar"}
        except Exception:
            pass

    return {
        "success": False,
        "error": "No QR code could be detected. Please ensure the QR code is clear, well-lit, and in focus."
    }
