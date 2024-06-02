import tkinter as tk  # Import the tkinter library for GUI
from tkinter import ttk  # Import ttk for themed widgets
from tkinter import filedialog  # Import filedialog for file dialogs
from tkinter import messagebox  # Import messagebox for displaying messages
from Crypto.Cipher import AES  # Import AES cipher for encryption
import os  # Import os module for file operations

# Define file types for file dialogs
file_types = [
    ("All Files", "*.*"),
    ("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
    ("Text Files", "*.txt"),
    ("PDF Files", "*.pdf"),
    ("Video Files", "*.mp4;*.avi;*.mov;*.mkv"),
    ("Audio Files", "*.mp3;*.wav;*.ogg;*.flac")
]

# Define EncryptionWindow class
class EncryptionWindow:
    def __init__(self, root, main_window):
        self.root = tk.Toplevel(root)  # Create a new top-level window
        self.main_window = main_window  # Reference to the main window
        self.root.title("SecureFile AES Tool - Encrypt File")  # Set window title
        self.create_ui()  # Create the user interface
        self.last_dir = ""  # Initialize last directory variable
        self.root.geometry("800x300")  # Set window size
        self.root.resizable(False, False)  # Disable window resizing
        self.root.configure(bg="#FFF5E0")  # Set background color

    # Method to encrypt a file
    def encrypt_file(self):
        input_file_path = self.input_file_entry.get()  # Get input file path from entry widget
        output_file_path = self.output_file_entry.get()  # Get output file path from entry widget
        key = self.key_entry.get()  # Get the encryption key as a string
        
        print("Encryption Key:", key)  # Print encryption key for debugging

        if len(key) != 32:  # Check if the key length is not 32 bytes
            messagebox.showerror("Error", "Encryption key must be exactly 32 characters long.")  # Show error message
            return  # Exit the method if key length is not 32

        initialization_vector = os.urandom(16)  # Generate a random initialization vector

        key_bytes = key.encode('utf-8')  # Convert key string to bytes

        cipher = AES.new(key_bytes, AES.MODE_CBC, initialization_vector)  # Create AES cipher object

        try:
            with open(input_file_path, 'rb') as infile:  # Open input file in binary mode
                with open(output_file_path, 'wb') as outfile:  # Open output file in binary mode
                    outfile.write(initialization_vector)  # Write initialization vector to output file
                    while True:
                        chunk = infile.read(4096)  # Read a chunk of data from input file
                        if not chunk:  # If end of file reached
                            break  # Exit the loop
                        elif len(chunk) % 16 != 0:  # If chunk size is not multiple of 16 bytes
                            chunk += b' ' * (16 - len(chunk) % 16)  # Pad the chunk with spaces
                        outfile.write(cipher.encrypt(chunk))  # Encrypt and write the chunk to output file

            messagebox.showinfo("Success", "File encrypted successfully.")  # Show success message
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")  # Show error message if an exception occurs

    # Method to verify the encryption key
    def verify_key(self):
        key = self.key_entry.get().encode()  # Get the encryption key as bytes
        if len(key) != 32:  # If key length is not 32 bytes
            messagebox.showerror("Error", "Encryption key must be exactly 32 characters long.")  # Show error message
        else:
            messagebox.showinfo("Success", "Encryption key is valid.")  # Show success message

    # Method to browse for input file
    def browse_input_file(self):
        file_type = self.file_type_var.get()  # Get selected file type
        file_filter = []  # Initialize file filter list
        if file_type == "All Files":  # If all files selected
            file_filter = [("All Files", "*.*")]  # Add all files filter
        elif file_type == "Images":  # If images selected
            file_filter = [("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")]  # Add images filter
        elif file_type == "Text Files":  # If text files selected
            file_filter = [("Text Files", "*.txt")]  # Add text files filter
        elif file_type == "PDF Files":  # If PDF files selected
            file_filter = [("PDF Files", "*.pdf")]  # Add PDF files filter
        elif file_type == "Video Files":  # If video files selected
            file_filter = [("Video Files", "*.mp4;*.avi;*.mov;*.mkv")]  # Add video files filter
        elif file_type == "Audio Files":  # If audio files selected
            file_filter = [("Audio Files", "*.mp3;*.wav;*.ogg;*.flac")]  # Add audio files filter

        filename = filedialog.askopenfilename(filetypes=file_filter, initialdir=self.last_dir)  # Open file dialog to select input file

        if filename and filename.endswith('.enc'):  # If selected file is encrypted
            messagebox.showerror("Error", "You cannot select an encrypted file.")  # Show error message
            return  # Exit the method

        if filename:  # If a valid file is selected
            self.last_dir = os.path.dirname(filename)  # Update last directory
            self.input_file_entry.delete(0, tk.END)  # Clear input file entry
            self.input_file_entry.insert(0, filename)  # Insert selected file path into entry

    # Method to browse for output file
    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(defaultextension=".enc", initialdir=self.last_dir, filetypes=[("Encrypted Files", "*.enc")])  # Open file dialog to select output file
        if filename:  # If a valid file name is provided
            self.last_dir = os.path.dirname(filename)  # Update last directory
            self.output_file_entry.delete(0, tk.END)  # Clear output file entry
            self.output_file_entry.insert(0, filename)  # Insert selected file path into entry

    # Method to clear input fields
    def clear_input_fields(self):
        self.input_file_entry.delete(0, tk.END)  # Clear input file entry
        self.output_file_entry.delete(0, tk.END)  # Clear output file entry
        self.key_entry.delete(0, tk.END)  # Clear key entry

    # Method to cancel encryption and go back to main window
    def cancel(self):
        self.root.destroy()  # Destroy encryption window
        self.main_window.deiconify()  # Show main window again

    # Method to create the user interface
    def create_ui(self):
        self.root.configure(background="#FFF5E0")  # Set background color

        self.root.grid_rowconfigure(0, minsize=20)  # Configure grid row

        for i in range(2):
            self.root.grid_columnconfigure(i, minsize=20)  # Configure grid columns
        self.root.grid_columnconfigure(8, minsize=20)  # Configure grid column

        # Create radio buttons for selecting file type
        file_type_label = tk.Label(self.root, text="File Type:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        file_type_label.grid(row=1, column=2, padx=5, pady=5)

        self.file_type_var = tk.StringVar(self.root)
        self.file_type_var.set(file_types[0][0])

        for i, (file_type, _) in enumerate(file_types):
            row = 2 + i
            style = ttk.Style()
            style.configure('TRadiobutton', background='#FFF5E0')
            radio_button = ttk.Radiobutton(self.root, text=file_type, variable=self.file_type_var, value=file_type, style='TRadiobutton')
            radio_button.grid(row=row, column=2, columnspan=3, padx=(20, 20), pady=(5, 2), sticky="w")

        separator = ttk.Separator(self.root, orient='vertical')
        separator.grid(row=2, column=5, rowspan=len(file_types), sticky='ns', padx=10, pady=10)

        empty_label = tk.Label(self.root, text="", bg="#FFF5E0")
        empty_label.grid(row=2, column=4, rowspan=len(file_types), padx=5, pady=5)

        # Create input file entry and browse button
        input_file_label = tk.Label(self.root, text="Input File:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        input_file_label.grid(row=2, column=6, padx=5, pady=5)

        self.input_file_entry = tk.Entry(self.root, width=50)
        self.input_file_entry.grid(row=2, column=7, padx=(5, 10), pady=5)

        browse_input_button = tk.Button(self.root, text="Browse", command=self.browse_input_file,
                                        bg="#141E46", fg="white", font=("Helvetica", 10, "bold"),
                                        relief=tk.RAISED, borderwidth=3, width=10, height=1)
        browse_input_button.grid(row=2, column=8, padx=5, pady=5)
        browse_input_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")

        # Create output file entry and browse button
        output_file_label = tk.Label(self.root, text="Output File:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        output_file_label.grid(row=3, column=6, padx=5, pady=5)

        self.output_file_entry = tk.Entry(self.root, width=50)
        self.output_file_entry.grid(row=3, column=7, padx=(5, 10), pady=5)

        browse_output_button = tk.Button(self.root, text="Browse", command=self.browse_output_file,
                                         bg="#141E46", fg="white", font=("Helvetica", 10, "bold"),
                                         relief=tk.RAISED, borderwidth=3, width=10, height=1)
        browse_output_button.grid(row=3, column=8, padx=5, pady=5)
        browse_output_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")

        # Create encryption key entry and verify button
        key_label = tk.Label(self.root, text="Encryption Key:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        key_label.grid(row=4, column=6, padx=5, pady=5)

        self.key_entry= tk.Entry(self.root, width=50, show="*")
        self.key_entry.grid(row=4, column=7, padx=(5, 10), pady=5)

        verify_button = tk.Button(self.root, text="Verify Key", command=self.verify_key,
                                  bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                  relief=tk.RAISED, borderwidth=3, width=10, height=1)
        verify_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        verify_button.grid(row=4, column=8, padx=5, pady=5)

        # Create buttons for encryption, clearing fields, and canceling
        clear_button = tk.Button(self.root, text="Encrypt again", command=self.clear_input_fields,
                                 bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                 relief=tk.RAISED, borderwidth=3, width=15, height=1)
        clear_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        clear_button.grid(row=5, column=6, padx=5, pady=10)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_file,
                                   bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                   relief=tk.RAISED, borderwidth=3, width=10, height=1)
        encrypt_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        encrypt_button.grid(row=5, column=7, padx=5, pady=10)

        cancel_button = tk.Button(self.root, text="Back", command=self.cancel,
                                  bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                  relief=tk.RAISED, borderwidth=3, width=10, height=1)
        cancel_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        cancel_button.grid(row=5, column=8, padx=5, pady=10)  # Place the button in the grid
