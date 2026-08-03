import cv2

def decode_qr(image_path):
    print("Image Path:", image_path)

    image = cv2.imread(image_path)

    if image is None:
        print("ERROR: Image could not be loaded.")
        return None

    print("Image loaded successfully.")
    print("Image Shape:", image.shape)

    detector = cv2.QRCodeDetector()

    data, points, _ = detector.detectAndDecode(image)

    print("Decoded Data:", data)
    print("Points:", points)

    if data:
        return data

    return None