import tkinter as tk
from tkinter import ttk

# Create the main window of application
root = tk.Tk()
root.title("Key Generation")

# Create a frame for the input fields and labels
frame = tk.Frame(root)
frame.pack(padx=50, pady=50)

# Label and input for "ime"
ime_label = tk.Label(frame, text="Ime:")
ime_label.grid(row=0, column=0, padx=5, pady=5)
ime_entry = tk.Entry(frame)
ime_entry.grid(row=0, column=1, padx=5, pady=5)

# Label and input for "mejl"
mejl_label = tk.Label(frame, text="Mejl:")
mejl_label.grid(row=1, column=0, padx=5, pady=5)
mejl_entry = tk.Entry(frame)
mejl_entry.grid(row=1, column=1, padx=5, pady=5)

# Label and dropdown for "velicina kljuca"
velicina_label = tk.Label(frame, text="Velicina Kljuca:")
velicina_label.grid(row=2, column=0, padx=5, pady=5)
velicina_var = tk.StringVar(value="1024")
velicina_dropdown = ttk.Combobox(frame, textvariable=velicina_var)
velicina_dropdown['values'] = ("1024", "2048")
velicina_dropdown.grid(row=2, column=1, padx=5, pady=5)



# Function to handle button click
def generate_keys():
    name = ime_entry.get()
    email = mejl_entry.get()
    key_size = velicina_var.get()


    # Create a new (additional) window for password input
    password_window = tk.Toplevel(root)
    password_window.title("Enter Password")

    # Set the size of the window
    window_width = 300
    window_height = 150

    # Get the screen dimensions
    screen_width = password_window.winfo_screenwidth()
    screen_height = password_window.winfo_screenheight()

    # Calculate the position to center the window
    position_top = int(screen_height / 2 - window_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)

    # Set the geometry of the window
    password_window.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")

    # Label and input for "lozinka"

    lozinka_label = tk.Label(password_window, text="Enter the password:")
    lozinka_label.pack(padx=5, pady=5)
    # lozinka_entry = tk.Entry(password_window, show="*")   //ne vidi se tekst koji se unosi
    lozinka_entry = tk.Entry(password_window)
    lozinka_entry.pack(padx=5, pady=5)

    password = None

    def on_ok():
        nonlocal password
        password= lozinka_entry.get()
        print(f"Generating keys for {name} with email {email} and key size {key_size} and password {password}")

        # ovde sad treba da se sacuvaju svi ti podaci
        # da se generisu kljucevi (ili mogu i gore)
        # da se sifruje privatni kljuc ovom sifrom

        password_window.destroy()

    # Button to submit the password
    ok_button = tk.Button(password_window, text="OK", command=on_ok)
    ok_button.pack(pady=10)




# Button to generate new key pair
generate_button = tk.Button(root, text="Generisi novi par kljuceva", command=generate_keys)
generate_button.pack(pady=10)

# Start the main event loop
root.mainloop()
