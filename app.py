import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cv2
import os

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Image Steganography")
        self.root.geometry("600x400")
        self.create_widgets()
        
    def create_widgets(self):
        # Create notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        
        # Encryption Tab
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.create_encrypt_tab(self.encrypt_frame)
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        
        # Decryption Tab
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.create_decrypt_tab(self.decrypt_frame)
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        
        self.notebook.pack(expand=True, fill='both')
        
        # Status Bar
        self.status = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def create_encrypt_tab(self, frame):
        ttk.Label(frame, text="Source Image:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.encrypt_path = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encrypt_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_encrypt_image).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Secret Message:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.secret_msg = tk.Text(frame, height=5, width=40)
        self.secret_msg.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.encrypt_pwd = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encrypt_pwd, show='*', width=40).grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Encrypt & Save", command=self.perform_encryption).grid(row=3, column=1, pady=10)

    def create_decrypt_tab(self, frame):
        ttk.Label(frame, text="Encrypted Image:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.decrypt_path = tk.StringVar()
        ttk.Entry(frame, textvariable=self.decrypt_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_decrypt_image).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.decrypt_pwd = tk.StringVar()
        ttk.Entry(frame, textvariable=self.decrypt_pwd, show='*', width=40).grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Decrypt", command=self.perform_decryption).grid(row=2, column=1, pady=10)

        self.decrypted_msg = tk.StringVar()
        ttk.Label(frame, text="Decrypted Message:").grid(row=3, column=0, padx=5, pady=5, sticky='e')
        ttk.Label(frame, textvariable=self.decrypted_msg, wraplength=400).grid(row=3, column=1, padx=5, pady=5)

    def browse_encrypt_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if path:
            self.encrypt_path.set(path)

    def browse_decrypt_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if path:
            self.decrypt_path.set(path)

    def update_status(self, message):
        self.status.config(text=message)
        self.root.update_idletasks()

    def xor_crypt(self, text, password):
        return ''.join([chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(text)])

    def perform_encryption(self):
        image_path = self.encrypt_path.get()
        message = self.secret_msg.get("1.0", tk.END).strip()
        password = self.encrypt_pwd.get()

        if not all([image_path, message, password]):
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Invalid image file")

            # Encrypt message
            encrypted = self.xor_crypt(message, password)
            encrypted_bytes = encrypted.encode('latin-1')
            data_len = len(encrypted_bytes).to_bytes(4, 'big')
            data = data_len + encrypted_bytes

            # Check capacity
            if len(data) > img.size:
                raise ValueError("Message too large for image. Use a larger image or shorter message.")

            # Embed data
            flat = img.reshape(-1)
            for i in range(len(data)):
                flat[i] = data[i]

            # Save encrypted image
            save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                    filetypes=[("PNG Image", "*.png"), ("JPEG Image", "*.jpg")])
            if save_path:
                cv2.imwrite(save_path, img)
                self.update_status(f"Encryption successful! Saved to {save_path}")
                os.system(f'start {save_path}')

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Encryption failed")

    def perform_decryption(self):
        image_path = self.decrypt_path.get()
        password = self.decrypt_pwd.get()

        if not all([image_path, password]):
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Invalid image file")

            # Extract data
            flat = img.reshape(-1)
            data_len = int.from_bytes(bytes(flat[:4]), 'big')
            encrypted_bytes = bytes(flat[4:4+data_len])
            
            if len(encrypted_bytes) != data_len:
                raise ValueError("Invalid or corrupted data")

            encrypted = encrypted_bytes.decode('latin-1')
            decrypted = self.xor_crypt(encrypted, password)
            
            self.decrypted_msg.set(decrypted)
            self.update_status("Decryption successful")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Decryption failed")
            self.decrypted_msg.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
