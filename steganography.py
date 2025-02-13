import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import cv2
import numpy as np
import os
import hashlib
from cryptography.fernet import Fernet
import base64
from tkinter.font import Font
from PIL import Image, ImageTk

class ModernButton(ttk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def on_enter(self, e):
        self['style'] = 'Hover.TButton'
        
    def on_leave(self, e):
        self['style'] = 'TButton'

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("800x600")
        self.root.configure(bg="#f5f6f7")
        self.root.minsize(800, 600)
        
        # Configure styles
        self.setup_styles()
        
        # Create main container
        self.main_container = ttk.Frame(root, padding="20", style='Main.TFrame')
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Header
        header_frame = ttk.Frame(self.main_container, style='Header.TFrame')
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        ttk.Label(header_frame, 
                 text="Secure Image Steganography", 
                 style='Header.TLabel').grid(row=0, column=0, pady=10)
        ttk.Label(header_frame,
                 text="Hide encrypted messages in images securely",
                 style='Subheader.TLabel').grid(row=1, column=0)
        
        # Create two main sections
        self.create_encode_section()
        self.create_decode_section()
        
        # Preview frame
        self.preview_frame = ttk.LabelFrame(self.main_container, text="Image Preview", padding="10", style='Preview.TLabelframe')
        self.preview_frame.grid(row=1, column=1, rowspan=2, sticky=(tk.N, tk.S, tk.E, tk.W), padx=(20, 0))
        self.preview_label = ttk.Label(self.preview_frame, text="No image selected")
        self.preview_label.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Status bar
        self.status_frame = ttk.Frame(self.main_container, style='Status.TFrame')
        self.status_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(20, 0))
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.status_frame, 
                                    textvariable=self.status_var,
                                    style='Status.TLabel')
        self.status_label.grid(row=0, column=0, sticky=(tk.W))
        
        # Configure grid weights
        self.main_container.columnconfigure(1, weight=1)
        self.main_container.rowconfigure(1, weight=1)
        self.main_container.rowconfigure(2, weight=1)
        
        self.image_path = None
        
    def setup_styles(self):
        style = ttk.Style()
        
        # Configure colors
        style.configure('Main.TFrame', background='#f5f6f7')
        style.configure('Header.TFrame', background='#f5f6f7')
        style.configure('Status.TFrame', background='#f5f6f7')
        
        # Header styles
        style.configure('Header.TLabel',
                       font=('Helvetica', 24, 'bold'),
                       background='#f5f6f7',
                       foreground='#2c3e50')
        style.configure('Subheader.TLabel',
                       font=('Helvetica', 12),
                       background='#f5f6f7',
                       foreground='#7f8c8d')
        
        # Button styles
        style.configure('TButton',
                       font=('Helvetica', 10),
                       padding=10)
        style.configure('Hover.TButton',
                       background='#3498db')
        
        # Section styles
        style.configure('Section.TLabelframe',
                       background='#ffffff',
                       padding=15)
        style.configure('Section.TLabelframe.Label',
                       font=('Helvetica', 12, 'bold'),
                       background='#ffffff',
                       foreground='#2c3e50')
        
        # Preview frame style
        style.configure('Preview.TLabelframe',
                       background='#ffffff',
                       padding=15)
        style.configure('Preview.TLabelframe.Label',
                       font=('Helvetica', 12, 'bold'),
                       background='#ffffff')
        
        # Status style
        style.configure('Status.TLabel',
                       font=('Helvetica', 10),
                       background='#f5f6f7',
                       foreground='#7f8c8d')
    
    def create_encode_section(self):
        encode_frame = ttk.LabelFrame(self.main_container, text="Encode Message", style='Section.TLabelframe')
        encode_frame.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), padx=(0, 10))
        
        # Add widgets with proper spacing
        ModernButton(encode_frame, 
                    text="Select Image",
                    command=self.select_image_encode).grid(row=0, column=0, pady=10, padx=5, sticky='ew')
        
        ModernButton(encode_frame,
                    text="Encode Message",
                    command=self.encode_message).grid(row=1, column=0, pady=10, padx=5, sticky='ew')
        
        # Add tooltips
        self.create_tooltip(encode_frame.winfo_children()[0],
                          "Select an image to hide your message in")
        self.create_tooltip(encode_frame.winfo_children()[1],
                          "Enter your message and password to encode")
    
    def create_decode_section(self):
        decode_frame = ttk.LabelFrame(self.main_container, text="Decode Message", style='Section.TLabelframe')
        decode_frame.grid(row=2, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), padx=(0, 10))
        
        ModernButton(decode_frame,
                    text="Select Image",
                    command=self.select_image_decode).grid(row=0, column=0, pady=10, padx=5, sticky='ew')
        
        ModernButton(decode_frame,
                    text="Decode Message",
                    command=self.decode_message).grid(row=1, column=0, pady=10, padx=5, sticky='ew')
        
        # Add tooltips
        self.create_tooltip(decode_frame.winfo_children()[0],
                          "Select an image containing a hidden message")
        self.create_tooltip(decode_frame.winfo_children()[1],
                          "Enter password to decode the hidden message")
    
    def create_tooltip(self, widget, text):
        def enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = ttk.Label(tooltip, text=text, background="#2c3e50",
                            foreground="white", padding=5)
            label.grid()
            
            widget.tooltip = tooltip
            
        def leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)
    
    def update_image_preview(self, image_path):
        try:
            # Read and resize image for preview
            img = Image.open(image_path)
            # Calculate new size maintaining aspect ratio
            display_size = (300, 300)
            img.thumbnail(display_size, Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(img)
            
            # Update preview label
            if hasattr(self, 'preview_photo'):
                self.preview_label.configure(image='')
            self.preview_photo = photo
            self.preview_label.configure(image=photo, text='')
            
        except Exception as e:
            self.preview_label.configure(text="Error loading preview", image='')
    
    def create_modern_toplevel(self, title, size="400x300"):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry(size)
        window.configure(bg="#f5f6f7")
        
        # Make it modal
        window.transient(self.root)
        window.grab_set()
        
        # Center on parent
        window.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - window.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - window.winfo_height()) // 2
        window.geometry(f"+{x}+{y}")
        
        return window

    def update_status(self, message, is_error=False):
        self.status_var.set(message)
        self.status_label.configure(foreground='#e74c3c' if is_error else '#7f8c8d')

    def get_encryption_key(self, password):
        # Generate a 32-byte key from the password using SHA-256
        key = hashlib.sha256(password.encode()).digest()
        # Convert to Fernet key format (32 url-safe base64-encoded bytes)
        return base64.urlsafe_b64encode(key)

    def encrypt_message(self, message, password):
        key = self.get_encryption_key(password)
        f = Fernet(key)
        return f.encrypt(message.encode())

    def decrypt_message(self, encrypted_message, password):
        key = self.get_encryption_key(password)
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()
        
    def select_image_encode(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if self.image_path:
            self.update_status(f"Selected image: {os.path.basename(self.image_path)}")
            self.update_image_preview(self.image_path)
    
    def select_image_decode(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("PNG files", "*.png")])
        if self.image_path:
            self.update_status(f"Selected image: {os.path.basename(self.image_path)}")
            self.update_image_preview(self.image_path)
    
    def encode_message(self):
        if not self.image_path:
            self.update_status("Please select an image first!", True)
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        # Create modern dialog
        message_window = self.create_modern_toplevel("Enter Message and Password", "500x400")
        
        # Message entry
        ttk.Label(message_window,
                 text="Enter your secret message:",
                 font=('Helvetica', 10, 'bold')).pack(pady=(20,5))
        text_widget = tk.Text(message_window, height=5, width=40)
        text_widget.pack(pady=5, padx=20)
        
        # Password entry
        ttk.Label(message_window,
                 text="Enter encryption password:",
                 font=('Helvetica', 10, 'bold')).pack(pady=(20,5))
        password_entry = ttk.Entry(message_window, show="•")
        password_entry.pack(pady=5)
        
        # Confirm password
        ttk.Label(message_window,
                 text="Confirm password:",
                 font=('Helvetica', 10, 'bold')).pack(pady=(10,5))
        confirm_password_entry = ttk.Entry(message_window, show="•")
        confirm_password_entry.pack(pady=5)
        
        def process_message():
            message = text_widget.get("1.0", tk.END).strip()
            password = password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            if not message or not password:
                messagebox.showerror("Error", "Please enter both message and password!")
                return
            
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            
            try:
                # Encrypt and encode message
                encrypted_message = self.encrypt_message(message, password)
                binary_message = ''.join(format(b, '08b') for b in encrypted_message)
                binary_message += '1111111111111110'  # Delimiter
                
                # Process image
                img = cv2.imread(self.image_path)
                if img is None:
                    raise ValueError("Could not read the image")
                
                if len(binary_message) > img.shape[0] * img.shape[1] * 3:
                    raise ValueError("Message too long for this image")
                
                # Encode message
                img_flat = img.flatten()
                binary_message_list = list(binary_message)
                binary_message_list.extend(['0'] * (len(img_flat) - len(binary_message_list)))
                
                for i in range(len(binary_message)):
                    img_flat[i] = (img_flat[i] & ~1) | int(binary_message_list[i])
                
                img_encoded = img_flat.reshape(img.shape)
                
                # Save encoded image
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    filetypes=[("PNG files", "*.png")])
                
                if save_path:
                    cv2.imwrite(save_path, img_encoded)
                    self.update_status("Message encoded successfully!")
                    message_window.destroy()
                    
            except Exception as e:
                self.update_status(f"Error: {str(e)}", True)
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                message_window.destroy()
        
        # Add encode button with modern style
        ModernButton(message_window,
                    text="Encode",
                    command=process_message).pack(pady=20)
    
    def decode_message(self):
        if not self.image_path:
            self.update_status("Please select an image first!", True)
            messagebox.showerror("Error", "Please select an image first!")
            return
        
        # Create modern password dialog
        password_window = self.create_modern_toplevel("Enter Password", "400x200")
        
        ttk.Label(password_window,
                 text="Enter decryption password:",
                 font=('Helvetica', 10, 'bold')).pack(pady=(20,5))
        password_entry = ttk.Entry(password_window, show="•")
        password_entry.pack(pady=10)
        
        def process_decode():
            password = password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter the password!")
                return
            
            try:
                # Read and process image
                img = cv2.imread(self.image_path)
                if img is None:
                    raise ValueError("Could not read the image")
                
                # Extract message
                binary_message = ''
                img_flat = img.flatten()
                
                for i in range(len(img_flat)):
                    binary_message += str(img_flat[i] & 1)
                    if len(binary_message) > 1000000:
                        break
                
                # Find delimiter and extract message
                delimiter = "1111111111111110"
                delimiter_index = binary_message.find(delimiter)
                if delimiter_index == -1:
                    raise ValueError("No hidden message found")
                
                binary_message = binary_message[:delimiter_index]
                encrypted_message = bytes(int(binary_message[i:i+8], 2) 
                                       for i in range(0, len(binary_message), 8))
                
                try:
                    decrypted_message = self.decrypt_message(encrypted_message, password)
                except:
                    raise ValueError("Incorrect password or corrupted message")
                
                # Show result in modern window
                result_window = self.create_modern_toplevel("Decoded Message", "500x300")
                
                ttk.Label(result_window,
                         text="Decoded Message:",
                         font=('Helvetica', 10, 'bold')).pack(pady=(20,5))
                
                text_widget = tk.Text(result_window, height=8, width=50)
                text_widget.pack(pady=10, padx=20)
                text_widget.insert("1.0", decrypted_message)
                text_widget.config(state='disabled')
                
                ModernButton(result_window,
                           text="Close",
                           command=result_window.destroy).pack(pady=10)
                
                self.update_status("Message decoded successfully!")
                password_window.destroy()
                
            except Exception as e:
                self.update_status(f"Error: {str(e)}", True)
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                password_window.destroy()
        
        ModernButton(password_window,
                    text="Decode",
                    command=process_decode).pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop() 