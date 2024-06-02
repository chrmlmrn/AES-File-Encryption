import tkinter as tk
from encryption import EncryptionWindow  # Importing EncryptionWindow class from encryption module
from decryption import DecryptionWindow  # Importing DecryptionWindow class from decryption module
from PIL import Image, ImageTk
import os

def center_window(window):
    """Function to center a Tkinter window on the screen"""
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x_offset = (window.winfo_screenwidth() - width) // 2
    y_offset = (window.winfo_screenheight() - height) // 2
    window.geometry(f"+{x_offset}+{y_offset}")

def exit_program():
    """Function to exit the program"""
    root.quit()

def open_encrypt_window():
    """Function to open the encryption window"""
    root.withdraw()  # Hide the main window
    encrypt_window = EncryptionWindow(root, main_window)  # Create an instance of EncryptionWindow
    encrypt_window.root.protocol("WM_DELETE_WINDOW", lambda: close_window(encrypt_window))  # Handle window close event

def open_decrypt_window():
    """Function to open the decryption window"""
    root.withdraw()  # Hide the main window
    decrypt_window = DecryptionWindow(root, main_window)  # Create an instance of DecryptionWindow
    decrypt_window.root.protocol("WM_DELETE_WINDOW", lambda: close_window(decrypt_window))  # Handle window close event

def close_window(window):
    """Function to close a window and show the main window"""
    window.destroy()
    root.deiconify()  # Show the main window again

root = tk.Tk()
root.title("SecureFile AES Tool")
root.geometry("500x580")
root.resizable(False, False)
root.configure(bg="#FFF5E0")

image_path = "SecureFileAESLogo.png"
if os.path.exists(image_path):
    logo_image = Image.open(image_path)
    logo_image = logo_image.resize((300, 300)) 
    logo_photo = ImageTk.PhotoImage(logo_image)
    logo_label = tk.Label(root, image=logo_photo, bg="#FFF5E0")
    logo_label.image = logo_photo  
    logo_label.grid(row=0, column=0, columnspan=2, pady=5)
else:
    print(f"Error: Image file '{image_path}' not found.")

button_width = 20
button_height = 2

main_window = root 
encrypt_button = tk.Button(root, text="Encrypt File", command=open_encrypt_window,
                           bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                           relief=tk.RAISED, borderwidth=5, width=button_width, height=button_height, bd=0, padx=5, pady=5)
encrypt_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
encrypt_button.grid(row=1, column=0, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=open_decrypt_window,
                           bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                           relief=tk.RAISED, borderwidth=5, width=button_width, height=button_height, bd=0, padx=5, pady=5)
decrypt_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
decrypt_button.grid(row=2, column=0, padx=10, pady=10)

exit_button = tk.Button(root, text="Exit", command=exit_program,
                        bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                        relief=tk.RAISED, borderwidth=5, width=button_width, height=button_height, bd=0, padx=5, pady=5)
exit_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
exit_button.grid(row=3, column=0, padx=10, pady=10)

root.grid_columnconfigure(0, weight=1)

center_window(root)  # Center the main window on the screen

root.mainloop()
