import tkinter as tk
from tkinter import ttk
from tkinter import messagebox # For error dialogs
from tkinter import filedialog # For "Browse..." button
from tkinter.scrolledtext import ScrolledText # For the output area
import subprocess
import sys
import os # For constructing paths reliably
import threading # For non-blocking stdout/stderr reading

def browse_script_path():
    # Start in the directory currently shown in the entry, or default to script's directory
    initial_dir_path = os.path.dirname(script_path_entry.get())
    if not os.path.isdir(initial_dir_path):
        initial_dir_path = os.path.dirname(os.path.abspath(__file__))

    filename = filedialog.askopenfilename(
        title="Select rvtools_data_generator.py",
        filetypes=(("Python files", "*.py"), ("All files", "*.*")),
        initialdir=initial_dir_path
    )
    if filename:
        script_path_entry.config(state=tk.NORMAL)
        script_path_entry.delete(0, tk.END)
        script_path_entry.insert(0, filename)
        # Keeping it normal/editable after selection, user might want to tweak
        # script_path_entry.config(state=tk.DISABLED)

def run_generator():
    script_path = script_path_entry.get()
    if not os.path.isfile(script_path):
        messagebox.showerror("Error", f"Generator script not found at: {script_path}\nPlease select a valid script path.")
        return

    try:
        num_rows = int(rows_entry.get())
        if num_rows <= 0:
            messagebox.showerror("Error", "Number of rows must be a positive integer.")
            return
    except ValueError:
        messagebox.showerror("Error", "Invalid input for number of rows. Please enter an integer.")
        return

    command = [sys.executable, script_path, "--rows", str(num_rows)]

    output_area.config(state=tk.NORMAL)
    output_area.delete('1.0', tk.END)
    output_area.insert(tk.END, f"Attempting to run generator with command: {' '.join(command)}\n\n")
    output_area.config(state=tk.DISABLED)

    try:
        # Using Popen for non-blocking execution.
        # bufsize=1 for line buffering, text=True for universal_newlines.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)

        print(f"Process started for {script_path} with PID: {process.pid}") # Console log for GUI runner

        # Function to stream output to the ScrolledText widget
        def stream_process_output(proc, out_text_widget):
            def enqueue_output(pipe, q_type):
                for line in iter(pipe.readline, ''):
                    out_text_widget.config(state=tk.NORMAL)
                    # Simple heuristic to distinguish from generator's own [INFO] etc.
                    prefix = f"[GUI-{q_type}]" if not line.strip().startswith("[") else ""
                    out_text_widget.insert(tk.END, f"{prefix}{line}")
                    out_text_widget.see(tk.END) # Scroll to the end
                    out_text_widget.config(state=tk.DISABLED)
                pipe.close()

            # Thread for stdout
            stdout_thread = threading.Thread(target=enqueue_output, args=(proc.stdout, "STDOUT"))
            stdout_thread.daemon = True
            stdout_thread.start()

            # Thread for stderr
            stderr_thread = threading.Thread(target=enqueue_output, args=(proc.stderr, "STDERR"))
            stderr_thread.daemon = True
            stderr_thread.start()

            # Function to check process completion and update GUI
            def check_process():
                if proc.poll() is not None: # Process has terminated
                    stdout_thread.join(timeout=1) # Attempt to join threads
                    stderr_thread.join(timeout=1)
                    out_text_widget.config(state=tk.NORMAL)
                    out_text_widget.insert(tk.END, f"\n[GUI-INFO] Process finished with exit code {proc.returncode}.\n")
                    if proc.returncode == 0:
                         messagebox.showinfo("Process Finished", "Data generation script completed successfully.")
                    else:
                         messagebox.showerror("Process Finished", f"Data generation script finished with error code: {proc.returncode}.")
                    out_text_widget.config(state=tk.DISABLED)
                else:
                    root.after(1000, check_process) # Check again after 1 second

            root.after(1000, check_process) # Initial check

        stream_process_output(process, output_area)
        messagebox.showinfo("Process Started", f"Data generation process started with {num_rows} rows.\nOutput will be streamed to the text area below.")

    except FileNotFoundError:
        messagebox.showerror("Error", f"Generator script not found at: {script_path}\nPlease ensure the path is correct.")
        output_area.config(state=tk.NORMAL)
        output_area.insert(tk.END, f"[GUI-ERROR] Generator script not found at {script_path}\n")
        output_area.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while trying to run the generator: {e}")
        output_area.config(state=tk.NORMAL)
        output_area.insert(tk.END, f"[GUI-ERROR] An error occurred: {e}\n")
        output_area.config(state=tk.DISABLED)

# Setup main window
root = tk.Tk()
root.title("RVTools Synthetic Data Generator - Setup")
root.geometry("700x550") # Increased size for output area

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

title_label = ttk.Label(main_frame, text="Generator Configuration", font=("Arial", 16))
title_label.pack(pady=10)

# --- Script Path ---
script_path_frame = ttk.Frame(main_frame)
script_path_frame.pack(fill=tk.X, pady=5)
ttk.Label(script_path_frame, text="Generator Script:").pack(side=tk.LEFT, padx=5)
script_path_entry = ttk.Entry(script_path_frame) # Width determined by expand
default_generator_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rvtools_data_generator.py")
script_path_entry.insert(0, default_generator_script_path)
script_path_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
# Browse button (Task 2)
browse_button = ttk.Button(script_path_frame, text="Browse...", command=browse_script_path)
browse_button.pack(side=tk.LEFT, padx=5)


# --- Number of Rows ---
rows_frame = ttk.Frame(main_frame)
rows_frame.pack(fill=tk.X, pady=5)
ttk.Label(rows_frame, text="Number of rows per CSV:").pack(side=tk.LEFT, padx=5)
rows_entry = ttk.Entry(rows_frame, width=10)
rows_entry.insert(0, "10")
rows_entry.pack(side=tk.LEFT, padx=5)

# --- Placeholder for AI Service Configuration ---
ai_config_frame = ttk.LabelFrame(main_frame, text="AI Service Configuration (Future)", padding="10")
ai_config_frame.pack(fill=tk.X, pady=10)
ttk.Label(ai_config_frame, text="AI Model Choice: [Dropdown Placeholder]").pack(pady=5)
ttk.Label(ai_config_frame, text="API Key: [Entry Placeholder]").pack(pady=5)

# --- Placeholder for Complexity Level ---
complexity_frame = ttk.LabelFrame(main_frame, text="Generation Complexity (Future)", padding="10")
complexity_frame.pack(fill=tk.X, pady=10)
ttk.Label(complexity_frame, text="Complexity Level: [Radio Button Group Placeholder: Simple, Medium, Fancy, Expert]").pack(pady=5)

# --- Action Button ---
run_button = ttk.Button(main_frame, text="Save Configuration & Run Generator", command=run_generator)
run_button.pack(pady=15)

# --- Output Display Area (Task 3) ---
output_label = ttk.Label(main_frame, text="Generator Output:")
output_label.pack(pady=(10,0), anchor=tk.W)
output_area = ScrolledText(main_frame, height=12, wrap=tk.WORD) # Adjusted height
output_area.pack(pady=5, fill=tk.BOTH, expand=True)
output_area.insert(tk.END, "Generator output will appear here...\n")
output_area.config(state=tk.DISABLED)

try:
    root.mainloop()
except Exception as e:
    print(f"Error running tkinter mainloop (expected in some environments): {e}")
    print("GUI blueprint setup complete.")
