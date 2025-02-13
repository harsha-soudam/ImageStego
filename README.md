# Image Steganography Application

This is a simple GUI application that allows you to hide secret messages within images using steganography techniques. The application uses the Least Significant Bit (LSB) method to embed text messages into images without noticeably affecting their appearance. Messages are encrypted using a password-based encryption system for additional security.

Checkout the project screenshots [Here](Outputs)

## Features

- User-friendly graphical interface
- Password-protected message encryption
- Secure message encoding and decoding
- Supports PNG, JPG, and BMP image formats for input
- Saves encoded images in PNG format to preserve data
- Uses OpenCV for efficient image processing
- Fernet symmetric encryption for message security

## Requirements

- Python 3.x
- OpenCV (opencv-python)
- cryptography

## Installation

1. Clone or download this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python steganography.py
```

2. To encode a message:
   - Click "Select Image" under the Encode section
   - Choose an image file
   - Click "Encode Message"
   - Enter your secret message in the popup window
   - Enter an encryption password
   - Click "Encode"
   - Choose where to save the encoded image (must be PNG format)

3. To decode a message:
   - Click "Select Image" under the Decode section
   - Choose an encoded PNG image
   - Click "Decode Message"
   - Enter the correct encryption password
   - The hidden message will be displayed in a popup window

## Notes

- The encoded output is always saved as a PNG file to prevent data loss
- The size of the message that can be hidden depends on the image dimensions
- For best results, use PNG images as input when encoding messages
- The application uses OpenCV for image processing, providing better performance and reliability
- Messages are encrypted using Fernet symmetric encryption before being hidden in the image
- You must remember the password used for encoding to successfully decode the message

## Security Considerations

- The application uses strong encryption (Fernet) for the message content
- Passwords are processed using SHA-256 hashing
- The LSB steganography method, while visually undetectable, can be detected through statistical analysis
- Always use strong passwords for better security
- The security of the hidden message depends on keeping the password secret 
