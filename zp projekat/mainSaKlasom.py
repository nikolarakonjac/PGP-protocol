import tkinter as tk
from tkinter import ttk

class KeyGenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Key Generation")

        # Create a frame for the input fields and labels
        frame = tk.Frame(root)
        frame.pack(padx=50, pady=50)

        # Label and input for "ime"
        ime_label = tk.Label(frame, text="Ime:")
        ime_label.grid(row=0, column=0, padx=5, pady=5)
        self.ime_entry = tk.Entry(frame)
        self.ime_entry.grid(row=0, column=1, padx=5, pady=5)

        # Label and input for "mejl"
        mejl_label = tk.Label(frame, text="Mejl:")
        mejl_label.grid(row=1, column=0, padx=5, pady=5)
        self.mejl_entry = tk.Entry(frame)
        self.mejl_entry.grid(row=1, column=1, padx=5, pady=5)

        # Label and dropdown for "velicina kljuca"
        velicina_label = tk.Label(frame, text="Velicina Kljuca:")
        velicina_label.grid(row=2, column=0, padx=5, pady=5)
        self.velicina_var = tk.StringVar(value="1024")
        self.velicina_dropdown = ttk.Combobox(frame, textvariable=self.velicina_var)
        self.velicina_dropdown['values'] = ("1024", "2048")
        self.velicina_dropdown.grid(row=2, column=1, padx=5, pady=5)

        # Button to generate new key pair
        generate_button = tk.Button(root, text="Generisi novi par kljuceva", command=self.generate_keys)
        generate_button.pack(pady=10)

    def generate_keys(self):
        ime = self.ime_entry.get()
        mejl = self.mejl_entry.get()
        velicina = self.velicina_var.get()
        print(f"Generating keys for {ime} with email {mejl} and key size {velicina}")

        # Create a new window for password input
        self.password_window = tk.Toplevel(self.root)
        self.password_window.title("Enter Password")

        # Set the size of the window
        window_width = 300
        window_height = 150

        # Get the screen dimensions
        screen_width = self.password_window.winfo_screenwidth()
        screen_height = self.password_window.winfo_screenheight()

        # Calculate the position to center the window
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)

        # Set the geometry of the window
        self.password_window.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")

        # Label and input for "lozinka"
        lozinka_label = tk.Label(self.password_window, text="Unesi Lozinku:")
        lozinka_label.pack(padx=5, pady=5)
        self.lozinka_entry = tk.Entry(self.password_window, show="*")
        self.lozinka_entry.pack(padx=5, pady=5)

        # Button to submit the password
        ok_button = tk.Button(self.password_window, text="OK", command=self.on_ok)
        ok_button.pack(pady=10)

    def on_ok(self):
        self.password = self.lozinka_entry.get()
        print(f"Password entered: {self.password}")  # You can use this password later in the class
        self.password_window.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = KeyGenApp(root)
    root.mainloop()
