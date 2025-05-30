"""
Drone Command & Control Interface GUI
This GUI is designed to control the drone's command and control interface, including starting/stopping the server, connecting/disconnecting clients, and managing the Certificate Authority (CA).

Usage:
cd ctf-networks-challenges

python -m tls.gui
"""
import threading
import logging
import subprocess
import sys
import queue
from typing import Any, Optional
import io
import os

import tkinter as tk
from tkinter import scrolledtext, LabelFrame, simpledialog, Menu
from tkinter.scrolledtext import ScrolledText

from .ctf_server import CTFServer

# Helper function to stream output from subprocess pipes
def stream_output(pipe: io.TextIOWrapper, queue: queue.Queue[Any], source: str):
    """Reads every character from a subprocess pipe (no waiting on '\\n')."""
    try:
        with pipe:
            while True:
                ch = pipe.read(1)
                if not ch:
                    break
                queue.put((source, ch))
    except Exception as e:
        logging.error(f"Error reading output from {source}: {e}")
    finally:
        queue.put((source, None))

class CTFGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Drone Command & Control Interface")
        self.root.geometry("800x650")
        self.root.configure(bg="#2E2E2E")

        self.server: Optional[CTFServer] = None # Initialize later after creating queues
        self.client_process = None
        self.ca_process = None
        self.server_thread = None
        self.client_stdin = None
        self.ca_client_stdin = None

        # Queues for communication with server thread
        self.client_update_queue: queue.Queue[Any] = queue.Queue()
        self.client_message_queue: queue.Queue[Any] = queue.Queue()
        self.subprocess_output_queue: queue.Queue[Any] = queue.Queue() # Queue for subprocess stdout/stderr
        self.client_output_buffer = {} # To store output per client process
        self.output_lines: dict[str, str] = {} # To store output lines for each source
        self.client_list: list[str] = [] # List to keep track of connected clients

        # Initialize server with queues
        self.server = CTFServer(
            client_update_queue=self.client_update_queue,
            client_message_queue=self.client_message_queue
        )

        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        self.server_logger = logging.getLogger('server')
        self.create_widgets()
        self.server_logger.addHandler(GuiHandler(self.server_log_text))

        # make sure to set the logging level for the GUI handler
        self._make_context_menu(self.server_log_text)
        self._make_context_menu(self.client_output_text)

        # Start processing queues
        self.root.after(100, self._process_queues)

    def _make_context_menu(self, widget: tk.Text) -> None:
        context_menu = Menu(widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: self._copy_text(widget))

        def show_menu(event: tk.Event) -> None:  # type: ignore[name-defined]
            context_menu.tk_popup(event.x_root, event.y_root)  # type: ignore[attr-defined]

        widget.bind("<Button-3>", show_menu)  # type: ignore

    def _copy_text(self, widget: tk.Text) -> None:
        try:
            if widget.tag_ranges(tk.SEL):  # type: ignore[attr-defined]
                selected_text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)  # type: ignore[attr-defined]
                self.root.clipboard_clear()  # type: ignore[attr-defined]
                self.root.clipboard_append(selected_text)  # type: ignore[attr-defined]
                logging.debug("Text copied to clipboard.")
        except tk.TclError:
            logging.debug("No text selected to copy.")
        except Exception as e:
            logging.error(f"Error copying text: {e}")

    def create_widgets(self) -> None:
        self.root.configure(bg="#2E2E2E")
        try:
            self.root.iconbitmap("documents/drone.ico")  # type: ignore[attr-defined]
        except tk.TclError:
            logging.warning("Icon file not found, continuing without icon")
        self.root.resizable(False, False)  # type: ignore[attr-defined]
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)  # type: ignore[attr-defined]

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

        # Sub-frame for buttons and proxy inputs
        client_control_frame = tk.Frame(client_frame, bg="#333333")
        client_control_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.connect_collaborator_button = tk.Button(client_control_frame, text="Connect Collaborator (Server Client)", command=self._start_server_client_process_with_proxy, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.connect_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.connect_ca_collaborator_button = tk.Button(client_control_frame, text="Connect CA Collaborator", command=self.start_ca_client_with_proxy, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.NORMAL)
        self.connect_ca_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_collaborator_button = tk.Button(client_control_frame, text="Disconnect Client Process", command=self._stop_client_process, bg="#444444", fg="#EEEEEE", font=("Consolas", 9), state=tk.DISABLED)
        self.disconnect_collaborator_button.pack(side=tk.LEFT, padx=5)

        # --- INPUT ENTRY ---
        self.client_input_label = tk.Label(client_control_frame, text="Send Command:", fg="#EEEEEE", bg="#333333", font=("Consolas", 9))
        self.client_input_label.pack(side=tk.LEFT, padx=(10, 5))
        # Use fill=tk.X and expand=True without fixed width
        self.client_input = tk.Entry(client_control_frame, bg="#555555", fg="#EEEEEE", insertbackground="#EEEEEE", font=("Consolas", 9))
        self.client_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)) # Added padding
        self.client_input.bind("<Return>", self._send_client_input_to_process)  # type: ignore
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

    def _ask_proxy_preference(self) -> bool:
        """Asks the user for their Burp proxy preference."""
        answer = simpledialog.askstring("Proxy Preference", "Use Burp proxy? (y/n):", parent=self.root)
        return answer.lower().startswith('y') if answer is not None else False

    def _start_server_client_process_with_proxy(self) -> None:
        use_proxy = self._ask_proxy_preference()
        self._start_client_process("client.py", "Collaborator", use_proxy)

    def start_ca_client_with_proxy(self) -> None:
        use_proxy = self._ask_proxy_preference()
        self._start_client_process("ca_client.py", "CA Collaborator", use_proxy)

    def _start_server_thread(self) -> None:
        # Check if thread exists AND is alive
        if self.server_thread is None or not self.server_thread.is_alive():
            try:
                # Reset server running flag before starting
                if self.server is not None:
                    self.server.running = True  # type: ignore[attr-defined]
                    self.server_thread = threading.Thread(target=self.server.run)  # type: ignore[attr-defined]
                    self.server_thread.daemon = True
                    self.server_thread.start()
                # Update button states AFTER successful start
                self.start_server_button.config(state=tk.DISABLED)
                self.stop_server_button.config(state=tk.NORMAL)
            except threading.ThreadError as e:
                logging.error(f"Error starting server thread: {e}")
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
        else:
            logging.warning("Drone Core (Server) is already running.")
        pass

    def stop_server(self, log_stopping: bool = True) -> None:
        # Check if thread exists AND is alive before trying to stop
        if self.server_thread and self.server_thread.is_alive():
            try:
                if log_stopping:
                    logging.info("Attempting to terminate Drone Core...")
                if self.server is not None:
                    self.server.running = False  # type: ignore[attr-defined]
                self.server_thread.join(timeout=1)
                self._clear_all_logs()
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
                self.server_thread = None
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error stopping server: {e}")
                self._clear_all_logs()
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
                self.server_thread = None
        else:
            if log_stopping:
                logging.warning("Drone Core (Server) is not running or already stopped.")
            self.start_server_button.config(state=tk.NORMAL)
            self.stop_server_button.config(state=tk.DISABLED)
            self.server_thread = None
            self._clear_all_logs()

    def _start_ca_process(self) -> None:
        # Check if process exists AND is running (poll() is None means running)
        if self.ca_process is None or self.ca_process.poll() is not None:
            try:
                # Use -u for unbuffered output
                command = [sys.executable, "-u", "-m", "tls.server_challenges.ca_challenge"]
                # Redirect stdout and stderr
                self.ca_process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True, # Decode output as text
                    encoding='utf-8', # Specify encoding
                    errors='replace', # Handle potential decoding errors
                    bufsize=0 # Unbuffered
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

    def stop_ca_process(self, log_stopping: bool = True) -> None:
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

    def _start_client_process(self, script_name: str, client_type: str, use_proxy: bool) -> None:
        module_path = f"tls.{script_name.replace('.py', '')}"
        if self.client_process is None or self.client_process.poll() is not None:
            try:
                logging.info(f"Starting {client_type} ({script_name}) with proxy: {use_proxy}")
                # Use -u for unbuffered output
                command = [sys.executable, "-u", "-m", module_path]
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                self.client_process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    text=True,
                    bufsize=0
                )
                if client_type == "Collaborator":
                    self.client_stdin = self.client_process.stdin
                elif client_type == "CA Collaborator":
                    self.ca_client_stdin = self.client_process.stdin
                threading.Thread(target=stream_output, args=(self.client_process.stdout, self.subprocess_output_queue, f"{client_type}_OUT"), daemon=True).start()
                if self.client_process and self.client_process.stdin:
                    proxy_answer = 'y\n' if use_proxy else 'n\n'
                    self.client_process.stdin.write(proxy_answer)
                    self.client_process.stdin.flush()
                    logging.info(f"Sent proxy preference '{proxy_answer.strip()}' to {client_type}")
                self.connect_collaborator_button.config(state=tk.DISABLED)
                self.connect_ca_collaborator_button.config(state=tk.DISABLED)
                self.disconnect_collaborator_button.config(state=tk.NORMAL)
                logging.info(f"{client_type} subprocess initiated.")
            except FileNotFoundError:
                logging.error(f"Error: Could not find Python executable or module '{module_path}'.")
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
            except Exception as e:
                logging.error(f"Error starting {client_type} subprocess: {e}")
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
        else:
            logging.warning(f"{client_type} subprocess is already running.")

    def _stop_client_process(self, log_stopping: bool = True) -> None:
        if self.client_process and self.client_process.poll() is None:
            try:
                if log_stopping:
                    logging.info("Attempting to terminate client process...")
                if self.client_process.stdin:
                    try:
                        self.client_process.stdin.close()
                    except Exception:
                        pass
                self.client_process.terminate()
                self.client_process.wait(timeout=1)
                if log_stopping:
                    logging.info("Client process terminated.")
            except subprocess.TimeoutExpired:
                if log_stopping:
                    logging.warning("Client process did not terminate gracefully, killing...")
                self.client_process.kill()
                self.client_process.wait()
                if log_stopping:
                    logging.info("Client process killed.")
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error stopping client process: {e}")
            finally:
                self.connect_collaborator_button.config(state=tk.NORMAL)
                self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                self.disconnect_collaborator_button.config(state=tk.DISABLED)
                self.client_process = None
                self.client_stdin = None
                self.ca_client_stdin = None
        else:
            if log_stopping:
                logging.warning("No client process is active or already stopped.")
            self.connect_collaborator_button.config(state=tk.NORMAL)
            self.connect_ca_collaborator_button.config(state=tk.NORMAL)
            self.disconnect_collaborator_button.config(state=tk.DISABLED)
            self.client_process = None
            self.client_stdin = None
            self.ca_client_stdin = None

    def _send_client_input_to_process(self, event: tk.Event) -> None:  # type: ignore[name-defined]
        command = self.client_input.get()
        # Determine which client to send the command to (currently only one)
        if self.client_process and self.client_process.poll() is None and self.client_process.stdin:
            self.client_process.stdin.write(command + '\n')
            self.client_process.stdin.flush()
            self.client_input.delete(0, tk.END)
            logging.info(f"Sent command: '{command}' to client process.")
        elif not self.client_process or self.client_process.poll() is not None:
            logging.warning("No active client process tosend command to.")
        else:
            logging.error("Client process stdin is not available.")

    def _add_client_to_list(self, client_id: str) -> None:
        current_items = list(self.client_listbox.get(0, tk.END))  # type: ignore[attr-defined]
        if client_id not in current_items:
            self.client_listbox.insert(tk.END, client_id)  # type: ignore[attr-defined]
            logging.info(f"GUI: Bot {client_id} connected.")

    def _remove_client_from_list(self, client_id: str) -> None:
        try:
            items = list(self.client_listbox.get(0, tk.END))  # type: ignore[attr-defined]
            if client_id in items:
                index = items.index(client_id)  # type: ignore
                self.client_listbox.delete(index)  # type: ignore[attr-defined]
                logging.info(f"GUI: Bot {client_id} disconnected.")
        except tk.TclError:
            pass

    def _display_client_output(self, source: str, message: str) -> None:
        try:
            self.client_output_text.configure(state='normal')  # type: ignore[attr-defined]
            if source not in self.output_lines:
                self.output_lines[source] = ""
            self.output_lines[source] += message
            if '\n' in self.output_lines[source]:
                line, rest = self.output_lines[source].split('\n', 1)
                self.client_output_text.insert(tk.END, f"[{source}]: {line}\n")  # type: ignore[attr-defined]
                self.output_lines[source] = rest
            self.client_output_text.see(tk.END)  # type: ignore[attr-defined]
            self.client_output_text.configure(state='disabled')  # type: ignore[attr-defined]
        except tk.TclError:
            pass

    def _process_queues(self) -> None:
        """Process updates from the server thread and subprocess queues."""
        try:
            # Process client connection updates from the server
            while not self.client_update_queue.empty():
                update_type, client_id = self.client_update_queue.get_nowait()
                if update_type == 'connect':
                    self._add_client_to_list(client_id)
                    if client_id in self.output_lines:
                        self.output_lines[client_id] = ""
                elif update_type == 'disconnect':
                    self._remove_client_from_list(client_id)
                    if client_id in self.output_lines:
                        self.output_lines[client_id] = ""
                        self._clear_client_output_display()

            # Process messages from the server to specific clients (if any)
            while not self.client_message_queue.empty():
                client_id, message = self.client_message_queue.get_nowait()
                self._display_client_output(client_id, message + '\n') # Add newline for server messages

            # Accumulate per-source buffer and flush as chars arrive
            while not self.subprocess_output_queue.empty():
                source, chunk = self.subprocess_output_queue.get_nowait()
                if source not in self.output_lines:
                    self.output_lines[source] = ""
                if chunk is None:
                    if self.output_lines[source]:
                        self._display_client_output(source, self.output_lines[source] + '\n')
                    self.output_lines[source] = ""
                    continue
                self._display_client_output(source, chunk)
        except queue.Empty:
            pass
        except Exception as e:
            logging.error(f"GUI Error processing queue: {e}")
        finally:
            self.root.after(100, self._process_queues)  # type: ignore[attr-defined]

    def _clear_all_logs(self) -> None:
        """Clear all log displays"""
        try:
            # Clear server log
            self.server_log_text.configure(state='normal')  # type: ignore[attr-defined]
            self.server_log_text.delete('1.0', tk.END)  # type: ignore[attr-defined]
            self.server_log_text.configure(state='disabled')  # type: ignore[attr-defined]
            
            # Clear client output
            self._clear_client_output_display()
            
            # Reset output lines dictionary to prevent old data from appearing
            for key in list(self.output_lines.keys()):
                self.output_lines[key] = ""
            
            logging.debug("All logs cleared")
        except tk.TclError:
            pass
        except Exception as e:
            logging.error(f"Error clearing logs: {e}")
    
    def _clear_client_output_display(self) -> None:
        """Clear the client output text widget."""
        try:
            self.client_output_text.configure(state='normal')  # type: ignore[attr-defined]
            self.client_output_text.delete('1.0', tk.END)  # type: ignore[attr-defined]
            self.client_output_text.configure(state='disabled')  # type: ignore[attr-defined]
        except tk.TclError:
            pass

    def _on_closing(self) -> None:
        """Handles the event when the user clicks the 'X' button."""
        logging.info("Close button clicked. Shutting down...")
        # Attempt to stop all running components without excessive logging
        self.stop_server(log_stopping=False)
        self.stop_ca_process(log_stopping=False)
        self._stop_client_process(log_stopping=False)

        logging.info("Exiting application.")
        # Cancel the scheduled queue check before destroying
        # This requires storing the after_id, let's simplify for now
        # and rely on root.destroy() cleaning things up.
        self.root.destroy()  # type: ignore[attr-defined]

class GuiHandler(logging.Handler):
    def __init__(self, text_widget: ScrolledText) -> None:
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        self.log_level_tags = {
            logging.DEBUG: 'DEBUG',
            logging.INFO: 'INFO',
            logging.WARNING: 'WARNING',
            logging.ERROR: 'ERROR',
            logging.CRITICAL: 'CRITICAL',
        }

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        tag = self.log_level_tags.get(record.levelno, 'INFO')
        try:
            self.text_widget.configure(state='normal')  # type: ignore[attr-defined]
            self.text_widget.insert(tk.END, msg + '\n', (tag,))  # type: ignore[attr-defined]
            self.text_widget.see(tk.END)  # type: ignore[attr-defined]
            self.text_widget.configure(state='disabled')  # type: ignore[attr-defined]
        except tk.TclError:
            pass
        except Exception as e:
            print(f"Error in GuiHandler: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    gui = CTFGui(root)
    root.mainloop()
    # Clean up on exit