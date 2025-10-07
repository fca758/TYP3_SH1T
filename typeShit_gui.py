"""GUI wrapper for typeShit CLI functions.

This file provides a simple Tkinter GUI that reuses the placeholder
functions defined in `typeShit.py`: encriptacionArchivo, desencriptarArchivo,
and generadorDeClave. The GUI is intentionally simple and synchronous; it
calls the functions directly and shows their textual output in a scrolled
text widget.

Usage:
    python typeShit_gui.py

Note: the real encryption/decryption implementations should be placed in the
existing functions in `typeShit.py` or in dedicated modules and imported here.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import io
import sys
from typing import Optional

# Import functions from CLI scaffold; if you later move them, update imports.
try:
    from typeShit import encriptacionArchivo, desencriptarArchivo, generadorDeClave
except Exception:
    # If import fails, create simple fallbacks so GUI can still run.
    def encriptacionArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
        print("[ENCRYPT fallback]", input_file, output_file, key, algorithm)

    def desencriptarArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
        print("[DECRYPT fallback]", input_file, output_file, key, algorithm)

    def generadorDeClave(algorithm: Optional[str]) -> None:
        print("[KEYGEN fallback]", algorithm)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TYP3_SH1T GUI")
        self.geometry("640x420")
        self.resizable(False, False)

        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Action: Encrypt / Decrypt
        ttk.Label(frm, text="Acción:").grid(column=0, row=0, sticky=tk.W)
        self.action_var = tk.StringVar(value="encrypt")
        action_combo = ttk.Combobox(frm, textvariable=self.action_var, values=["encrypt", "decrypt"], state="readonly", width=12)
        action_combo.grid(column=1, row=0, sticky=tk.W)

        # Algorithm selection
        ttk.Label(frm, text="Algoritmo:").grid(column=0, row=1, sticky=tk.W)
        self.algorithm_var = tk.StringVar(value="AES-128")
        algo_combo = ttk.Combobox(frm, textvariable=self.algorithm_var, values=["AES-128", "AES-192", "AES-256"], state="readonly", width=12)
        algo_combo.grid(column=1, row=1, sticky=tk.W)

        # Input file
        ttk.Label(frm, text="Archivo entrada:").grid(column=0, row=2, sticky=tk.W)
        self.input_var = tk.StringVar()
        input_entry = ttk.Entry(frm, textvariable=self.input_var, width=50)
        input_entry.grid(column=1, row=2, columnspan=2, sticky=tk.W)
        ttk.Button(frm, text="Examinar", command=self.browse_input).grid(column=3, row=2, sticky=tk.W)

        # Key
        ttk.Label(frm, text="Clave:").grid(column=0, row=3, sticky=tk.W)
        self.key_var = tk.StringVar()
        key_entry = ttk.Entry(frm, textvariable=self.key_var, width=50)
        key_entry.grid(column=1, row=3, columnspan=2, sticky=tk.W)

        # Run button
        run_btn = ttk.Button(frm, text="Ejecutar", command=self.run_action)
        run_btn.grid(column=1, row=4, pady=(8, 8), sticky=tk.W)

        # Output text
        ttk.Label(frm, text="Salida:").grid(column=0, row=5, sticky=tk.NW)
        self.output_txt = tk.Text(frm, width=78, height=12, wrap=tk.WORD)
        self.output_txt.grid(column=0, row=6, columnspan=4, sticky=tk.W)

        # Simple grid padding
        for child in frm.winfo_children():
            child.grid_configure(padx=6, pady=4)

    def browse_input(self):
        path = filedialog.askopenfilename(title="Selecciona archivo")
        if path:
            self.input_var.set(path)

    def run_action(self):
        action = self.action_var.get()
        algo = self.algorithm_var.get()
        infile = self.input_var.get() or None
        key = self.key_var.get() or None

        if not infile:
            messagebox.showwarning("Falta archivo", "Debes seleccionar un archivo de entrada.")
            return

        # Capture stdout from the called functions to show in GUI
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            if action == "encrypt":
                encriptacionArchivo(infile, None, key, algorithm=algo)
            else:
                desencriptarArchivo(infile, None, key, algorithm=algo)
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al ejecutar la acción: {e}")
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        self.output_txt.delete("1.0", tk.END)
        self.output_txt.insert(tk.END, output)


if __name__ == "__main__":
    app = App()
    app.mainloop()
