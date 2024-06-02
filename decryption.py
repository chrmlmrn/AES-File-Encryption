import tkinter as tk  # Import the tkinter library for GUI
from tkinter import ttk  # Import themed tkinter for better look
from tkinter import filedialog  # Import filedialog for opening and saving files
from tkinter import messagebox  # Import messagebox for displaying messages
from Crypto.Cipher import AES  # Import AES cipher from Crypto library
import os  # Import os module for file operations

# Define DecryptionWindow class
class DecryptionWindow:
    def __init__(self, root, main_window):
        self.root = tk.Toplevel(root)  # Create a new Toplevel window
        self.root.title("SecureFile AES Tool - Decrypt File")  # Set window title
        self.main_window = main_window  # Reference to main window
        self.create_ui()  # Create the user interface
        self.root.geometry("800x290")  # Set window size
        self.root.resizable(False, False)  # Disable window resizing
        self.root.configure(bg="#FFF5E0")  # Set background color

    # Method to decrypt a file
    def decrypt_file(self):
        input_file_path = self.input_file_entry.get()  # Get input file path
        output_file_path = self.output_file_entry.get()  # Get output file path
        key = self.key_entry.get()  # Get decryption key

        print("Decryption Key:", key)  # Print the key

        if len(key) != 32:  # Check if key length is not 32 characters
            messagebox.showerror("Error", "Decryption key must be exactly 32 characters long.")  # Show error message
            return  # Exit the method
        
        key_bytes = key.encode('utf-8')  # Convert key to bytes

        try:
            with open(input_file_path, 'rb') as infile:
                initialization_vector = infile.read(16)  # Read initialization vector from input file
                cipher = AES.new(key_bytes, AES.MODE_CBC, initialization_vector)  # Create AES cipher object

                with open(output_file_path, 'wb') as outfile:
                    previous_chunk = initialization_vector
                    while True:
                        chunk = infile.read(4096)  # Read chunk of data from input file
                        if not chunk:
                            break
                        decrypted_chunk = cipher.decrypt(chunk)  # Decrypt the chunk
                        outfile.write(decrypted_chunk)  # Write decrypted data to output file
                        previous_chunk = chunk

                    padding_length = previous_chunk[-1]  # Get length of padding
                    outfile.seek(-padding_length, os.SEEK_END)  # Seek to the end of file excluding padding
                    outfile.truncate()  # Truncate the file to remove padding

            messagebox.showinfo("Success", "File decrypted successfully.")  # Show success message
        except ValueError:
            messagebox.showerror("Error", "Invalid decryption key. Please ensure that the correct key is provided.")  # Show error message
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")  # Show error message

    # Method to browse for input file
    def browse_input_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])  # Open file dialog for selecting input file
        if filename:
            self.input_file_entry.delete(0, tk.END)  # Clear input file entry
            self.input_file_entry.insert(0, filename)  # Insert selected file path into input file entry

    # Method to browse for output file
    def browse_output_file(self):
        filename = filedialog.asksaveasfilename()  # Open file dialog for selecting output file
        self.output_file_entry.delete(0, tk.END)  # Clear output file entry
        self.output_file_entry.insert(0, filename)  # Insert selected file path into output file entry

    # Method to clear input fields
    def clear_input_fields(self):
        self.input_file_entry.delete(0, tk.END)  # Clear input file entry
        self.output_file_entry.delete(0, tk.END)  # Clear output file entry
        self.key_entry.delete(0, tk.END)  # Clear key entry
        self.result_label.config(text="")  # Clear result label

    # Method to verify the decryption key
    def verify_key(self):
        key = self.key_entry.get().encode()  # Get key and encode to bytes
        if len(key) != 32:  # Check if key length is not 32 characters
            messagebox.showerror("Error", "Decryption key must be exactly 32 characters long.")  # Show error message
        else:
            messagebox.showinfo("Success", "Decryption key is valid.")  # Show success message

    # Method to go back to the main window
    def back_to_main_window(self):
        self.root.destroy()  # Destroy the decryption window
        self.main_window.deiconify()  # Show the main window

    # Method to create the user interface
    def create_ui(self):
        self.root.configure(background="#FFF5E0")  # Set background color

        # Configure grid layout
        self.root.grid_rowconfigure(0, minsize=50)
        for i in range(6):
            self.root.grid_columnconfigure(i, minsize=50)  
        self.root.grid_rowconfigure(5, minsize=20)

        # Create input file label and entry
        input_file_label = tk.Label(self.root, text="Encrypted File:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        input_file_label.grid(row=1, column=2, padx=5, pady=5)
        self.input_file_entry = tk.Entry(self.root, width=50)
        self.input_file_entry.grid(row=1, column=3, padx=(5, 10), pady=5)  

        # Create button to browse input file
        browse_input_button = tk.Button(self.root, text="Browse", command=self.browse_input_file,
                                        bg="#141E46", fg="white", font=("Helvetica", 10, "bold"),
                                        relief=tk.RAISED, borderwidth=3, width=10, height=1)
        browse_input_button.grid(row=1, column=4, padx=5, pady=5)
        browse_input_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")

        # Create output file label and entry
        output_file_label = tk.Label(self.root, text="Decrypted File:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        output_file_label.grid(row=2, column=2, padx=5, pady=5)
        self.output_file_entry = tk.Entry(self.root, width=50)
        self.output_file_entry.grid(row=2, column=3, padx=(5, 10), pady=5)

        # Create button to browse output file
        browse_output_button = tk.Button(self.root, text="Browse", command=self.browse_output_file,
                                         bg="#141E46", fg="white", font=("Helvetica", 10, "bold"),
                                         relief=tk.RAISED, borderwidth=3, width=10, height=1)
        browse_output_button.grid(row=2, column=4, padx=5, pady=5)
        browse_output_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")

        # Create decryption key label and entry
        key_label = tk.Label(self.root, text="Decryption Key:", bg="#FFF5E0", font=("Helvetica", 12, "bold"))
        key_label.grid(row=3, column=2, padx=5, pady=5)
        self.key_entry= tk.Entry(self.root, width=50, show="*")
        self.key_entry.grid(row=3, column=3, padx=(5, 10), pady=5)

        # Create button to verify key
        verify_button = tk.Button(self.root, text="Verify Key", command=self.verify_key,
                                  bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                  relief=tk.RAISED, borderwidth=3, width=10, height=1)
        verify_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        verify_button.grid(row=3, column=4, padx=5, pady=5)

        # Create button to clear input fields
        clear_button = tk.Button(self.root, text="Decrypt again", command=self.clear_input_fields,
                                 bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                 relief=tk.RAISED, borderwidth=3, width=15, height=1)
        clear_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        clear_button.grid(row=4, column=2, padx=5, pady=10)  

        # Create button to decrypt file
        decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_file,
                                   bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                   relief=tk.RAISED, borderwidth=3, width=10, height=1)
        decrypt_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        decrypt_button.grid(row=4, column=3, padx=5, pady=10)  

        # Create button to go back to main window
        back_button = tk.Button(self.root, text="Back", command=self.back_to_main_window,
                                  bg="#141E46", fg="white", font=("Helvetica", 12, "bold"),
                                  relief=tk.RAISED, borderwidth=3, width=10, height=1)
        back_button.config(borderwidth=0, highlightthickness=0, relief='flat', highlightbackground="#141E46")
        back_button.grid(row=4, column=4, padx=5, pady=10)  

        # Create label to display decryption result
        self.result_label = tk.Label(self.root, text="", bg="#FFF5E0")
        self.result_label.grid(row=5, column=2, columnspan=3, padx=5, pady=5)
