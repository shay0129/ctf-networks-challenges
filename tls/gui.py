"""
Drone Command & Control Interface GUI
This GUI is designed to control the drone's command and control interface, including starting/stopping the server, connecting/disconnecting clients, and managing the Certificate Authority (CA).

Usage:
python -m communication.tls.gui
"""
import threading
import logging
import subprocess
import sys
import queue
import io

from tkinter import scrolledtext, ttk, LabelFrame
import tkinter as tk

from .ctf_server import CTFServer

# Helper function to stream output from subprocess pipes
def stream_output(pipe: io.TextIOWrapper, queue: queue.Queue, source: str):
    """Reads lines from a subprocess pipe and puts them onto a queue."""
    try:
        with pipe: # Ensure pipe is closed eventually
            for line in iter(pipe.readline, ''):
                queue.put((source, line.strip()))
    except Exception as e:
        # Log errors reading from pipe, but don't crash the thread
        logging.error(f"Error reading output from {source}: {e}")
    finally:
        # Signal that this stream is done (optional, might be useful)
        queue.put((source, None))

class CTFGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Drone Command & Control Interface")
        self.root.geometry("800x600")
        self.root.configure(bg="#2E2E2E") # Dark background for a "malicious" look

        self.server = None # Initialize later after creating queues
        self.client_process = None
        self.ca_process = None
        self.server_thread = None

        # Queues for communication with server thread
        self.client_update_queue = queue.Queue()
        self.client_message_queue = queue.Queue()
        self.subprocess_output_queue = queue.Queue() # Queue for subprocess stdout/stderr


        # Initialize server with queues
        self.server = CTFServer(
            client_update_queue=self.client_update_queue,
            client_message_queue=self.client_message_queue
        )

        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        self.server_logger = logging.getLogger('server')
        self.create_widgets()
        self.server_logger.addHandler(GuiHandler(self.server_log_text))

        # Start processing queues
        self.root.after(100, self._process_queues)

    def create_widgets(self):
        """# --- Main Window Configuration ---"""
        self.root.configure(bg="#2E2E2E")
        self.root.iconbitmap("communication/tls/drone.ico")   # Set the icon for the window
        self.root.resizable(False, False)   # Disable resizing
        # --- Bind window close ('X') button to _on_closing method ---
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # --- "Drone Core" Frame (Server Control) ---
        server_frame = LabelFrame(self.root, text="Drone Core (Server Control)", fg="#FF4500", bg="#333333", font=("Consolas", 10))
        server_frame.pack(pady=10, padx=10, fill=tk.X)

        # Initialize button states correctly
        self.start_server_button = tk.Button(server_frame, text="Initialize Drone Core", command=self._start_server_thread, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.start_server_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_server_button = tk.Button(server_frame, text="Terminate Drone Core", command=self.stop_server, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.DISABLED)
        self.stop_server_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.start_ca_button = tk.Button(server_frame, text="Deploy Certificate Authority", command=self._start_ca_process, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.start_ca_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_ca_button = tk.Button(server_frame, text="Halt Certificate Authority", command=self.stop_ca_process, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.DISABLED)
        self.stop_ca_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.server_log_label = tk.Label(server_frame, text="Drone Core Log:", fg="#EEEEEE", bg="#333333", font=("Consolas", 9))
        self.server_log_label.pack(pady=(5, 0), padx=5, anchor=tk.W)
        self.server_log_text = scrolledtext.ScrolledText(server_frame, wrap=tk.WORD, width=60, height=8, bg="#444444", fg="#EEEEEE", font=("Consolas", 9))
        self.server_log_text.pack(pady=5, padx=5, fill=tk.X)
        # Configure tags for log colors
        self.server_log_text.tag_config('INFO', foreground='#EEEEEE') # Default
        self.server_log_text.tag_config('DEBUG', foreground='cyan')
        self.server_log_text.tag_config('WARNING', foreground='yellow')
        self.server_log_text.tag_config('ERROR', foreground='red')
        self.server_log_text.tag_config('CRITICAL', foreground='red', underline=True)
        self.server_log_text.configure(state='disabled') # Start disabled

        # --- "Connected Collaborators" Frame (Client Control) ---
        client_frame = LabelFrame(self.root, text="Connected Collaborators (Bots)", fg="#00FF7F", bg="#333333", font=("Consolas", 10))
        client_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True) # Changed fill/expand

        # Sub-frame for buttons and input
        client_control_frame = tk.Frame(client_frame, bg="#333333")
        client_control_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.connect_collaborator_button = tk.Button(client_control_frame, text="Connect Collaborator (Server Client)", command=self.start_server_client, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.connect_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.connect_ca_collaborator_button = tk.Button(client_control_frame, text="Connect CA Collaborator", command=self.start_ca_client, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.connect_ca_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_collaborator_button = tk.Button(client_control_frame, text="Disconnect Client Process", command=self.stop_client, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.DISABLED)
        self.disconnect_collaborator_button.pack(side=tk.LEFT, padx=5)

        # --- INPUT ENTRY ---
        self.client_input_label = tk.Label(client_control_frame, text="Send Command:", fg="#EEEEEE", bg="#333333", font=("Consolas", 9))
        self.client_input_label.pack(side=tk.LEFT, padx=(10, 5))
        # Use fill=tk.X and expand=True without fixed width
        self.client_input = tk.Entry(client_control_frame, bg="#555555", fg="#EEEEEE", insertbackground="#EEEEEE", font=("Consolas", 9))
        self.client_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)) # Added padding
        self.client_input.bind("<Return>", self.send_client_input)
        # --- END OF ADDED INPUT ENTRY ---

        # Frame to hold listbox and output area side-by-side
        client_display_frame = tk.Frame(client_frame, bg="#333333")
        client_display_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Listbox for connected clients
        self.client_list_label = tk.Label(client_display_frame, text="Active Bots:", fg="#EEEEEE", bg="#333333", font=("Consolas", 9))
        self.client_list_label.pack(side=tk.LEFT, anchor=tk.NW, padx=(0,5))
        self.client_listbox = tk.Listbox(client_display_frame, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), width=35, height=10) # Adjusted width
        self.client_listbox.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        # No TODO needed here anymore, handled by _process_queues

        # ScrolledText for client output
        self.client_output_label = tk.Label(client_display_frame, text="Bot Output:", fg="#EEEEEE", bg="#333333", font=("Consolas", 9))
        self.client_output_label.pack(side=tk.LEFT, anchor=tk.NW, padx=(10,5))
        self.client_output_text = scrolledtext.ScrolledText(client_display_frame, wrap=tk.WORD, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), height=10)
        self.client_output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.client_output_text.configure(state='disabled')
        # No TODO needed here anymore, handled by _process_queues

    def _start_server_thread(self):
        # Check if thread exists AND is alive
        if self.server_thread is None or not self.server_thread.is_alive():
            try:
                # Reset server running flag before starting
                self.server.running = True
                self.server_thread = threading.Thread(target=self.server.run)
                self.server_thread.daemon = True
                self.server_thread.start()
                # Update button states AFTER successful start
                self.start_server_button.config(state=tk.DISABLED)
                self.stop_server_button.config(state=tk.NORMAL)
                # logging.info("Drone Core initialization sequence started.")
            except threading.ThreadError as e:
                logging.error(f"Error starting server thread: {e}")
                # Ensure buttons are in correct state if start fails
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
        else:
            logging.warning("Drone Core (Server) is already running.")

        # Placeholder for any additional setup or checks
        pass 

    def stop_server(self, log_stopping=True): # Added optional logging control
        # Check if thread exists AND is alive before trying to stop
        if self.server_thread and self.server_thread.is_alive():
            try:
                if log_stopping:
                    logging.info("Attempting to terminate Drone Core...")
                self.server.running = False # Signal the server thread to stop
                self.server_thread.join(timeout=1) # Shorter timeout for closing

                if self.server_thread.is_alive():
                    if log_stopping:
                        logging.warning("Drone Core thread did not stop gracefully.")
                elif log_stopping:
                    logging.info("Drone Core terminated.")

            except Exception as e:
                if log_stopping:
                    logging.error(f"Error stopping server: {e}")
            finally:
                # Always update button states and reset thread variable after attempt
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
                self.server_thread = None # Reset thread variable
        else:
            if log_stopping:
                logging.warning("Drone Core (Server) is not running or already stopped.")
            # Ensure buttons reflect the stopped state even if called again
            self.start_server_button.config(state=tk.NORMAL)
            self.stop_server_button.config(state=tk.DISABLED)
            self.server_thread = None # Ensure reset

    def _start_ca_process(self):
        # Check if process exists AND is running (poll() is None means running)
        if self.ca_process is None or self.ca_process.poll() is not None:
            try:
                command = [sys.executable, "-m", "communication.tls.server_challenges.ca_challenge"]
                # Redirect stdout and stderr
                self.ca_process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True, # Decode output as text
                    encoding='utf-8', # Specify encoding
                    errors='replace', # Handle potential decoding errors
                    bufsize=1 # Line buffered
                )
                # Start threads to read output
                threading.Thread(target=stream_output, args=(self.ca_process.stdout, self.subprocess_output_queue, "CA_OUT"), daemon=True).start()
                threading.Thread(target=stream_output, args=(self.ca_process.stderr, self.subprocess_output_queue, "CA_ERR"), daemon=True).start()

                # Update button states AFTER successful start
                self.start_ca_button.config(state=tk.DISABLED)
                self.stop_ca_button.config(state=tk.NORMAL)
                logging.info("Certificate Authority deployment initiated.")
            except FileNotFoundError:
                # This might indicate the module path is wrong or python isn't in PATH
                logging.error("Error: Could not find Python executable or specified module.")
                self.start_ca_button.config(state=tk.NORMAL)
                self.stop_ca_button.config(state=tk.DISABLED)
            except Exception as e:
                logging.error(f"Error deploying Certificate Authority: {e}")
                self.start_ca_button.config(state=tk.NORMAL)
                self.stop_ca_button.config(state=tk.DISABLED)
        else:
            logging.warning("Certificate Authority is already deployed and running.")
        
        # Placeholder for any additional setup or checks
        pass

    def stop_ca_process(self, log_stopping=True): # Added optional logging control
        # Check if process exists AND is running (poll() is None means running)
        if self.ca_process and self.ca_process.poll() is None:
            try:
                if log_stopping:
                    logging.info("Attempting to halt Certificate Authority...")
                self.ca_process.terminate()
                self.ca_process.wait(timeout=1) # Wait for graceful termination
                if log_stopping:
                    logging.info("Certificate Authority halted.")
            except subprocess.TimeoutExpired:
                if log_stopping:
                    logging.warning("Certificate Authority did not terminate gracefully, killing...")
                self.ca_process.kill()
                self.ca_process.wait() # Wait after kill
                if log_stopping:
                    logging.info("Certificate Authority killed.")
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error halting Certificate Authority: {e}")
            finally:
                # Always update button states and reset process variable after attempt
                self.start_ca_button.config(state=tk.NORMAL)
                self.stop_ca_button.config(state=tk.DISABLED)
                self.ca_process = None # Reset process variable
        else:
            if log_stopping:
                logging.warning("Certificate Authority is not active or already stopped.")
            # Ensure buttons reflect the stopped state even if called again
            self.start_ca_button.config(state=tk.NORMAL)
            self.stop_ca_button.config(state=tk.DISABLED)
            self.ca_process = None # Ensure reset

    def start_server_client(self):
        self._start_client("client.py", "Collaborator")

    def start_ca_client(self):
        self._start_client("ca_client.py", "CA Collaborator")

    def _start_client(self, script_name, client_type):
        """Starts the client script as a module, output goes to terminal."""
        # Check if process exists AND is running
        if self.client_process is None or self.client_process.poll() is not None:
            try:
                logging.info(f"Starting {client_type} ({script_name}) as module... Output will appear in the terminal.")
                # Construct module path from script name
                module_path = f"communication.tls.{script_name.replace('.py', '')}"
                command = [sys.executable, "-m", module_path]
                self.client_process = subprocess.Popen(
                    command, # Use the new command
                    stdin=subprocess.PIPE,
                    text=True,
                    # Removed cwd, run from project root
                    bufsize=1
                )
                # Update button states AFTER successful start
                self.connect_collaborator_button.config(state=tk.DISABLED)
                self.connect_ca_collaborator_button.config(state=tk.DISABLED)
                self.disconnect_collaborator_button.config(state=tk.NORMAL)
                logging.info(f"{client_type} connection process initiated.")
            except FileNotFoundError:
                 # This might indicate the module path is wrong or python isn't in PATH
                logging.error(f"Error: Could not find Python executable or specified module ({module_path}).")
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
            except Exception as e:
                logging.error(f"Error starting {client_type}: {e}")
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
        else:
            logging.warning(f"{client_type} process is already running.")
        
        # Placeholder for any additional setup or checks
        pass

    def stop_client(self, log_stopping=True): # Added optional logging control
        # Check if process exists AND is running
        if self.client_process and self.client_process.poll() is None:
            try:
                if log_stopping:
                    logging.info("Attempting to terminate client process...")
                # Close stdin first to signal the client if it's waiting for input
                if self.client_process.stdin:
                    try:
                        self.client_process.stdin.close()
                    except Exception:
                        pass # Ignore errors closing stdin
                self.client_process.terminate()
                self.client_process.wait(timeout=1) # Shorter timeout
                if log_stopping:
                    logging.info("Client process terminated.")
            except subprocess.TimeoutExpired:
                if log_stopping:
                    logging.warning("Client process did not terminate gracefully, killing...")
                self.client_process.kill()
                self.client_process.wait() # Wait after kill
                if log_stopping:
                    logging.info("Client process killed.")
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error stopping client: {e}")
            finally:
                # Always update button states and reset process variable after attempt
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
                self.client_process = None # Reset the process variable
        else:
            if log_stopping:
                logging.warning("No client process is active or already stopped.")
            # Ensure buttons reflect the stopped state even if called again
            self.connect_collaborator_button.config(state=tk.NORMAL)
            self.connect_ca_collaborator_button.config(state=tk.NORMAL)
            self.disconnect_collaborator_button.config(state=tk.DISABLED)
            self.client_process = None # Ensure reset

    def send_client_input(self, event):
        command = self.client_input.get()
        if self.client_process and self.client_process.poll() is None and self.client_process.stdin:
            self.client_process.stdin.write(command + '\n')
            self.client_process.stdin.flush()
            self.client_input.delete(0, tk.END)
            logging.info(f"Sent command: '{command}' to client.")
        elif not self.client_process or self.client_process.poll() is not None:
            logging.warning("No active client to send command to.")
        else:
            logging.error("Client stdin is not available.")
        
        # Placeholder for any additional command handling or checks
        pass

    def _add_client_to_list(self, client_id):
        """Adds a client identifier to the listbox."""
        if client_id not in self.client_listbox.get(0, tk.END):
            self.client_listbox.insert(tk.END, client_id)
            logging.info(f"GUI: Bot {client_id} connected.")

    def _remove_client_from_list(self, client_id):
        """Removes a client identifier from the listbox."""
        try:
            items = list(self.client_listbox.get(0, tk.END))
            if client_id in items:
                index = items.index(client_id)
                self.client_listbox.delete(index)
                logging.info(f"GUI: Bot {client_id} disconnected.")
        except tk.TclError:
            pass # Ignore if listbox is already destroyed

    def _display_client_output(self, client_id, message):
        """Displays output from a specific client."""
        try:
            self.client_output_text.configure(state='normal')
            self.client_output_text.insert(tk.END, f"[{client_id}]: {message}\n")
            self.client_output_text.see(tk.END)
            self.client_output_text.configure(state='disabled')
        except tk.TclError:
            pass # Ignore if widget is destroyed

    def _process_queues(self):
        """Process updates from the server thread queues."""
        try:
            # Process client connection updates
            while not self.client_update_queue.empty():
                update_type, client_id = self.client_update_queue.get_nowait()
                if update_type == 'connect':
                    self._add_client_to_list(client_id)
                elif update_type == 'disconnect':
                    self._remove_client_from_list(client_id)

            # Process client messages
            while not self.client_message_queue.empty():
                client_id, message = self.client_message_queue.get_nowait()
                self._display_client_output(client_id, message)

        except queue.Empty:
            pass # No more items for now
        except Exception as e:
            logging.error(f"GUI Error processing queue: {e}")
        finally:
            # Reschedule the check
            self.root.after(100, self._process_queues)


    def _on_closing(self):
        """Handles the event when the user clicks the 'X' button."""
        logging.info("Close button clicked. Shutting down...")
        # Attempt to stop all running components without excessive logging
        self.stop_server(log_stopping=False)
        self.stop_ca_process(log_stopping=False)
        self.stop_client(log_stopping=False)

        logging.info("Exiting application.")
        # Cancel the scheduled queue check before destroying
        # This requires storing the after_id, let's simplify for now
        # and rely on root.destroy() cleaning things up.
        self.root.destroy() # Close the Tkinter window object and exit the application
        # sys.exit(0) # Usually not needed if root.destroy() is called

class GuiHandler(logging.Handler):
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        # Define log level tags (should match tag_config in create_widgets)
        self.log_level_tags = {
            logging.DEBUG: 'DEBUG',
            logging.INFO: 'INFO',
            logging.WARNING: 'WARNING',
            logging.ERROR: 'ERROR',
            logging.CRITICAL: 'CRITICAL',
        }

    def emit(self, record):
        msg = self.format(record)
        # Determine the tag based on log level
        tag = self.log_level_tags.get(record.levelno, 'INFO') # Default to INFO
        try:
            self.text_widget.configure(state='normal')
            # Insert message with the appropriate tag
            self.text_widget.insert(tk.END, msg + '\n', (tag,))
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        except tk.TclError:
            pass # Ignore errors if widget is destroyed
        except Exception as e:
            # Handle other potential errors during emit
            print(f"Error in GuiHandler: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    gui = CTFGui(root)
    root.mainloop()