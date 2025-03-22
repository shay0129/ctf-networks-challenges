import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import logging
import subprocess
from ctf_server import CTFServer

class CTFGui:
    def __init__(self, root):
        self.root = root
        self.root.title("CTF Server and Client GUI")
        
        self.create_widgets()
        self.server = CTFServer()
        self.client_process = None
        
        # Redirect logging to the GUI
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        self.server_logger = logging.getLogger('server')
        self.server_logger.addHandler(GuiHandler(self.server_log_text))
        
    def create_widgets(self):
        # Create start and stop buttons for the server
        self.start_server_button = tk.Button(self.root, text="Start Server", command=self.start_server)
        self.start_server_button.pack(pady=5)
        
        self.stop_server_button = tk.Button(self.root, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_server_button.pack(pady=5)
        
        # Create start and stop buttons for the client
        self.start_client_button = tk.Button(self.root, text="Start Client", command=self.start_client)
        self.start_client_button.pack(pady=5)
        
        self.stop_client_button = tk.Button(self.root, text="Stop Client", command=self.stop_client, state=tk.DISABLED)
        self.stop_client_button.pack(pady=5)
        
        # Create a dropdown menu for client mode selection
        self.client_mode = tk.StringVar(value="SERVER")
        self.client_mode_menu = ttk.Combobox(self.root, textvariable=self.client_mode, values=["CA", "SERVER"])
        self.client_mode_menu.pack(pady=5)
        
        # Create a scrolled text widget for server logging
        self.server_log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=10)
        self.server_log_text.pack(pady=5)
        
        # Create a scrolled text widget for client logging
        self.client_log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=10)
        self.client_log_text.pack(pady=5)
        
        # Create an entry widget for client input
        self.client_input = tk.Entry(self.root)
        self.client_input.pack(pady=5)
        self.client_input.bind("<Return>", self.send_client_input)
        
    def start_server(self):
        self.server_thread = threading.Thread(target=self.server.run)
        self.server_thread.start()
        self.start_server_button.config(state=tk.DISABLED)
        self.stop_server_button.config(state=tk.NORMAL)
        
    def stop_server(self):
        self.server.running = False
        self.server_thread.join()
        self.start_server_button.config(state=tk.NORMAL)
        self.stop_server_button.config(state=tk.DISABLED)
        
    def start_client(self):
        mode = self.client_mode.get()
        if mode == "SERVER":
            client_script = "server_client.py"
        else:
            client_script = "ca_client.py"
        self.client_process = subprocess.Popen(
            ["python", "-u", client_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            cwd="communication/tls"
        )
        self.start_client_button.config(state=tk.DISABLED)
        self.stop_client_button.config(state=tk.NORMAL)
        self.client_log_thread = threading.Thread(target=self.read_client_log)
        self.client_log_thread.start()
        
    def stop_client(self):
        if self.client_process:
            self.client_process.terminate()
            self.client_process.wait()
            self.start_client_button.config(state=tk.NORMAL)
            self.stop_client_button.config(state=tk.DISABLED)
        
    def read_client_log(self):
        while True:
            line = self.client_process.stdout.readline()
            if not line:
                break
            self.client_log_text.insert(tk.END, line)
            self.client_log_text.yview(tk.END)
        while True:
            line = self.client_process.stderr.readline()
            if not line:
                break
            self.client_log_text.insert(tk.END, line)
            self.client_log_text.yview(tk.END)
        
    def send_client_input(self, event):
        input_text = self.client_input.get() + "\n"
        self.client_process.stdin.write(input_text)
        self.client_process.stdin.flush()
        self.client_input.delete(0, tk.END)
        
class GuiHandler(logging.Handler):
    def __init__(self, log_widget):
        super().__init__()
        self.log_widget = log_widget
        
    def emit(self, record):
        msg = self.format(record)
        self.log_widget.insert(tk.END, msg + '\n')
        self.log_widget.yview(tk.END)

def main():
    root = tk.Tk()
    app = CTFGui(root)
    root.mainloop()

if __name__ == "__main__":
    main()