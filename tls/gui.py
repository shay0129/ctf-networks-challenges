# type: ignore[attr-defined]
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
        self.root.title("🚁 Operation BLACKBIRD - Drone Command & Control Interface")
        self.root.geometry("1000x750")
        self.root.configure(bg="#1a1a1a")
        self.root.resizable(True, True)  # Allow resizing for better user experience

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

        def show_menu(event: tk.Event) -> None:
            context_menu.tk_popup(event.x_root, event.y_root)

        widget.bind("<Button-3>", show_menu)

    def _copy_text(self, widget: tk.Text) -> None:
        try:
            if widget.tag_ranges(tk.SEL):
                selected_text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                # logging.debug("Text copied to clipboard.")        except tk.TclError:
            # logging.debug("No text selected to copy.")
            pass
        except Exception as e:
            logging.error(f"Error copying text: {e}")
    
    def create_widgets(self) -> None:
        self.root.configure(bg="#1a1a1a")
        try:
            self.root.iconbitmap("documents/drone.ico")
        except tk.TclError:
            # logging.warning("Icon file not found, continuing without icon")
            pass
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Create main container with padding
        main_container = tk.Frame(self.root, bg="#1a1a1a")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Mission Status Header ---
        header_frame = tk.Frame(main_container, bg="#1a1a1a")
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        mission_label = tk.Label(
            header_frame, 
            text="🎯 MISSION STATUS: Operation BLACKBIRD INTERCEPT", 
            fg="#FF6B35", 
            bg="#1a1a1a", 
            font=("Consolas", 14, "bold")
        )
        mission_label.pack()
        
        status_label = tk.Label(
            header_frame, 
            text="📡 Drone C&C Server | 🔐 Certificate Authority | 🤖 Bot Management", 
            fg="#A0A0A0", 
            bg="#1a1a1a", 
            font=("Consolas", 10)
        )
        status_label.pack()

        # --- "Drone Core" Frame (Server Control) ---
        server_frame = LabelFrame(
            main_container, 
            text="🚁 Drone Core (Server Control)", 
            fg="#FF6B35", 
            bg="#2a2a2a", 
            font=("Consolas", 11, "bold"),
            relief=tk.RIDGE,
            bd=2
        )
        server_frame.pack(pady=10, fill=tk.X)        # Button frame for better organization
        button_frame = tk.Frame(server_frame, bg="#2a2a2a")
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        # Initialize button states correctly
        self.start_server_button = tk.Button(
            button_frame, 
            text="🚀 Initialize Drone Core", 
            command=self._start_server_thread, 
            bg="#4a4a4a", 
            fg="#00FF7F", 
            font=("Consolas", 10, "bold"), 
            state=tk.NORMAL,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#00FF7F"
        )
        self.start_server_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_server_button = tk.Button(
            button_frame, 
            text="🛑 Terminate Drone Core", 
            command=self.stop_server, 
            bg="#4a4a4a", 
            fg="#FF6B6B", 
            font=("Consolas", 10, "bold"), 
            state=tk.DISABLED,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#FF6B6B"
        )
        self.stop_server_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.start_ca_button = tk.Button(
            button_frame, 
            text="🔐 Deploy Certificate Authority", 
            command=self._start_ca_process, 
            bg="#4a4a4a", 
            fg="#FFD93D", 
            font=("Consolas", 10, "bold"), 
            state=tk.NORMAL,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#FFD93D"
        )
        self.start_ca_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_ca_button = tk.Button(
            button_frame, 
            text="🔒 Halt Certificate Authority", 
            command=self.stop_ca_process, 
            bg="#4a4a4a", 
            fg="#FF6B6B", 
            font=("Consolas", 10, "bold"), 
            state=tk.DISABLED,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#FF6B6B"
        )
        self.stop_ca_button.pack(side=tk.LEFT, padx=5, pady=5)        # Server log section
        log_frame = tk.Frame(server_frame, bg="#2a2a2a")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.server_log_label = tk.Label(
            log_frame, 
            text="📊 Drone Core Activity Log:", 
            fg="#A0A0A0", 
            bg="#2a2a2a", 
            font=("Consolas", 10, "bold")
        )
        self.server_log_label.pack(pady=(5, 2), anchor=tk.W)
        
        self.server_log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=10, 
            bg="#0d1117", 
            fg="#c9d1d9", 
            font=("Consolas", 9),
            insertbackground="#c9d1d9",
            selectbackground="#264f78",
            relief=tk.SUNKEN,
            bd=2
        )
        self.server_log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for log colors (GitHub Dark theme inspired)
        self.server_log_text.tag_config('INFO', foreground='#7c3aed')      # Purple
        self.server_log_text.tag_config('DEBUG', foreground='#06b6d4')     # Cyan  
        self.server_log_text.tag_config('WARNING', foreground='#f59e0b')   # Amber
        self.server_log_text.tag_config('ERROR', foreground='#ef4444')     # Red
        self.server_log_text.tag_config('CRITICAL', foreground='#dc2626', underline=True)  # Dark red
        self.server_log_text.configure(state='disabled')        # --- "Connected Collaborators" Frame (Client Control) ---
        client_frame = LabelFrame(
            main_container, 
            text="🤖 Connected Collaborators (Bot Network)", 
            fg="#00FF7F", 
            bg="#2a2a2a", 
            font=("Consolas", 11, "bold"),
            relief=tk.RIDGE,
            bd=2
        )
        client_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Sub-frame for buttons and proxy inputs
        client_control_frame = tk.Frame(client_frame, bg="#2a2a2a")
        client_control_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.connect_collaborator_button = tk.Button(
            client_control_frame, 
            text="🔗 Connect Collaborator (Server Client)", 
            command=self._start_server_client_process_with_proxy, 
            bg="#4a4a4a", 
            fg="#00FF7F", 
            font=("Consolas", 10, "bold"), 
            state=tk.NORMAL,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#00FF7F"
        )
        self.connect_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.connect_ca_collaborator_button = tk.Button(
            client_control_frame, 
            text="🔐 Connect CA Collaborator", 
            command=self.start_ca_client_with_proxy, 
            bg="#4a4a4a", 
            fg="#FFD93D", 
            font=("Consolas", 10, "bold"), 
            state=tk.NORMAL,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#FFD93D"
        )
        self.connect_ca_collaborator_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_collaborator_button = tk.Button(
            client_control_frame, 
            text="⚠️ Disconnect Client Process", 
            command=self._stop_client_process, 
            bg="#4a4a4a", 
            fg="#FF6B6B", 
            font=("Consolas", 10, "bold"), 
            state=tk.DISABLED,
            relief=tk.RAISED,
            bd=2,
            activebackground="#5a5a5a",
            activeforeground="#FF6B6B"
        )
        self.disconnect_collaborator_button.pack(side=tk.LEFT, padx=5)        # --- INPUT ENTRY ---
        input_frame = tk.Frame(client_control_frame, bg="#2a2a2a")
        input_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        self.client_input_label = tk.Label(
            input_frame, 
            text="📡 Send Command:", 
            fg="#A0A0A0", 
            bg="#2a2a2a", 
            font=("Consolas", 10, "bold")
        )
        self.client_input_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.client_input = tk.Entry(
            input_frame, 
            bg="#0d1117", 
            fg="#c9d1d9", 
            insertbackground="#c9d1d9", 
            font=("Consolas", 10),
            relief=tk.SUNKEN,
            bd=2,
            selectbackground="#264f78"
        )
        self.client_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.client_input.bind("<Return>", self._send_client_input_to_process)
        # --- END OF ADDED INPUT ENTRY ---        # Frame to hold listbox and output area side-by-side
        client_display_frame = tk.Frame(client_frame, bg="#2a2a2a")
        client_display_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel for active bots
        left_panel = tk.Frame(client_display_frame, bg="#2a2a2a")
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.client_list_label = tk.Label(
            left_panel, 
            text="🤖 Active Bots:", 
            fg="#A0A0A0", 
            bg="#2a2a2a", 
            font=("Consolas", 10, "bold")
        )
        self.client_list_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Listbox with scrollbar
        listbox_frame = tk.Frame(left_panel, bg="#2a2a2a")
        listbox_frame.pack(fill=tk.Y)
        
        self.client_listbox = tk.Listbox(
            listbox_frame, 
            bg="#0d1117", 
            fg="#c9d1d9", 
            font=("Consolas", 9), 
            width=40, 
            height=12,
            selectbackground="#264f78",
            selectforeground="#ffffff",
            relief=tk.SUNKEN,
            bd=2
        )
        self.client_listbox.pack(side=tk.LEFT, fill=tk.Y)
        
        # Scrollbar for listbox
        listbox_scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.client_listbox.config(yscrollcommand=listbox_scrollbar.set)
        listbox_scrollbar.config(command=self.client_listbox.yview)

        # Right panel for output
        right_panel = tk.Frame(client_display_frame, bg="#2a2a2a")
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.client_output_label = tk.Label(
            right_panel, 
            text="📊 Bot Output & Communications:", 
            fg="#A0A0A0", 
            bg="#2a2a2a", 
            font=("Consolas", 10, "bold")
        )
        self.client_output_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.client_output_text = scrolledtext.ScrolledText(
            right_panel, 
            wrap=tk.WORD, 
            bg="#0d1117", 
            fg="#c9d1d9", 
            font=("Consolas", 9), 
            height=12,
            insertbackground="#c9d1d9",
            selectbackground="#264f78",            relief=tk.SUNKEN,
            bd=2
        )
        self.client_output_text.pack(fill=tk.BOTH, expand=True)
        self.client_output_text.configure(state='disabled')

        # --- Status Bar ---
        status_frame = tk.Frame(main_container, bg="#1a1a1a", relief=tk.SUNKEN, bd=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        self.status_label = tk.Label(
            status_frame, 
            text="🔴 Status: Drone Core Offline | CA: Offline | Bots: 0 Connected", 
            fg="#A0A0A0", 
            bg="#1a1a1a", 
            font=("Consolas", 9),
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Mission timer
        self.mission_time_label = tk.Label(
            status_frame, 
            text="⏱️ Mission Time: 00:00:00", 
            fg="#A0A0A0", 
            bg="#1a1a1a", 
            font=("Consolas", 9)
        )
        self.mission_time_label.pack(side=tk.RIGHT, padx=5, pady=2)
        
        # Initialize mission timer
        import time
        self.mission_start_time = time.time()
        self._update_mission_timer()

        # Add keyboard shortcuts
        self._setup_keyboard_shortcuts()

    def _setup_keyboard_shortcuts(self) -> None:
        """Setup keyboard shortcuts for common actions"""
        # Ctrl+S: Start server
        self.root.bind('<Control-s>', lambda e: self._start_server_thread() if self.start_server_button['state'] == tk.NORMAL else None)
        
        # Ctrl+T: Stop server  
        self.root.bind('<Control-t>', lambda e: self.stop_server() if self.stop_server_button['state'] == tk.NORMAL else None)
        
        # Ctrl+C: Start CA
        self.root.bind('<Control-c>', lambda e: self._start_ca_process() if self.start_ca_button['state'] == tk.NORMAL else None)
        
        # Ctrl+Q: Quit application
        self.root.bind('<Control-q>', lambda e: self._on_closing())
        
        # F5: Refresh status
        self.root.bind('<F5>', lambda e: self._update_status_bar())
        
        # Focus on input field with Ctrl+I
        self.root.bind('<Control-i>', lambda e: self.client_input.focus_set())

    def _show_help_dialog(self) -> None:
        """Show keyboard shortcuts help dialog"""
        from tkinter import messagebox
        help_text = """
🎯 Operation BLACKBIRD - Keyboard Shortcuts:

Ctrl+S - Start Drone Core
Ctrl+T - Stop Drone Core  
Ctrl+C - Start Certificate Authority
Ctrl+Q - Quit Application
Ctrl+I - Focus Command Input
F5 - Refresh Status

🚁 Mission Phases:
1. ICMP Challenge - Network packet timing
2. CA Challenge - Certificate infiltration 
3. Enigma Challenge - Cryptographic analysis

📡 Use the command input to interact with bots
🤖 Monitor bot activity in the output panel
        """
        messagebox.showinfo("Operation BLACKBIRD - Help", help_text)

    def _start_server_client_process_with_proxy(self) -> None:
        use_proxy = self._ask_proxy_preference()
        self._start_client_process("server_client.py", "Collaborator", use_proxy)

    def start_ca_client_with_proxy(self) -> None:
        use_proxy = self._ask_proxy_preference()
        self._start_client_process("ca_client.py", "CA Collaborator", use_proxy)

    def _start_server_thread(self) -> None:
        # Check if thread exists AND is alive
        if self.server_thread is None or not self.server_thread.is_alive():
            try:
                # Reset server running flag before starting
                if self.server is not None:
                    self.server.running = True
                    self.server_thread = threading.Thread(target=self.server.run)
                    self.server_thread.daemon = True
                    self.server_thread.start()                # Update button states AFTER successful start
                self.start_server_button.config(state=tk.DISABLED)
                self.stop_server_button.config(state=tk.NORMAL)
                self._update_status_bar()
            except threading.ThreadError as e:
                logging.error(f"Error starting server thread: {e}")
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
        else:
            # logging.warning("Drone Core (Server) is already running.")
            pass
        pass

    def stop_server(self, log_stopping: bool = True) -> None:
        # Check if thread exists AND is alive before trying to stop
        if self.server_thread and self.server_thread.is_alive():
            try:
                if log_stopping:
                    logging.info("Attempting to terminate Drone Core...")
                if self.server is not None:
                    self.server.running = False
                self.server_thread.join(timeout=1)
                self._clear_all_logs()
                self._clear_client_listbox()  # Clear Active Bots list
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
                self.server_thread = None
                self._update_status_bar()
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error stopping server: {e}")
                self._clear_all_logs()
                self._clear_client_listbox()  # Clear Active Bots list
                self.start_server_button.config(state=tk.NORMAL)
                self.stop_server_button.config(state=tk.DISABLED)
                self.server_thread = None
                self._update_status_bar()
        else:
            if log_stopping:
                # logging.warning("Drone Core (Server) is not running or already stopped.")
                pass
            self.start_server_button.config(state=tk.NORMAL)
            self.stop_server_button.config(state=tk.DISABLED)
            self.server_thread = None
            self._clear_all_logs()
            self._clear_client_listbox()  # Clear Active Bots list
            self._update_status_bar()

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
                threading.Thread(target=stream_output, args=(self.ca_process.stderr, self.subprocess_output_queue, "CA_ERR"), daemon=True).start()                # Update button states AFTER successful start
                self.start_ca_button.config(state=tk.DISABLED)
                self.stop_ca_button.config(state=tk.NORMAL)
                self._update_status_bar()
                # logging.info("Certificate Authority deployment initiated.")
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
            # logging.warning("Certificate Authority is already deployed and running.")
            pass
        # Placeholder for any additional setup or checks
        pass

    def stop_ca_process(self, log_stopping: bool = True) -> None:
        # Check if process exists AND is running (poll() is None means running)
        if self.ca_process and self.ca_process.poll() is None:
            try:
                if log_stopping:
                    # logging.info("Attempting to halt Certificate Authority...")
                    pass
                self.ca_process.terminate()
                self.ca_process.wait(timeout=1) # Wait for graceful termination
                if log_stopping:
                    # logging.info("Certificate Authority halted.")
                    pass
            except subprocess.TimeoutExpired:
                if log_stopping:
                    # logging.warning("Certificate Authority did not terminate gracefully, killing...")
                    pass
                self.ca_process.kill()
                self.ca_process.wait() # Wait after kill
                if log_stopping:
                    # logging.info("Certificate Authority killed.")
                    pass
            except Exception as e:
                if log_stopping:
                    logging.error(f"Error halting Certificate Authority: {e}")
            finally:
                self.start_ca_button.config(state=tk.NORMAL)
                self.stop_ca_button.config(state=tk.DISABLED)
                self.ca_process = None # Reset process variable
                self._clear_all_logs()  # Clear logs when CA server stops
                self._clear_client_listbox()  # Clear Active Bots list
        else:
            if log_stopping:
                # logging.warning("Certificate Authority is not active or already stopped.")
                pass
            self.start_ca_button.config(state=tk.NORMAL)
            self.stop_ca_button.config(state=tk.DISABLED)
            self.ca_process = None # Ensure reset
            self._clear_all_logs()  # Clear logs when CA server stops
            self._clear_client_listbox()  # Clear Active Bots list

    def _start_client_process(self, script_name: str, client_type: str, use_proxy: bool) -> None:
        module_path = f"tls.{script_name.replace('.py', '')}"
        if self.client_process is None or self.client_process.poll() is not None:
            try:
                # logging.info(f"Starting {client_type} ({script_name}) with proxy: {use_proxy}")
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
                    # logging.info(f"Sent proxy preference '{proxy_answer.strip()}' to {client_type}")
                self.connect_collaborator_button.config(state=tk.DISABLED)
                self.connect_ca_collaborator_button.config(state=tk.DISABLED)
                self.disconnect_collaborator_button.config(state=tk.NORMAL)
                # logging.info(f"{client_type} subprocess initiated.")
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
            # logging.warning(f"{client_type} subprocess is already running.")
            pass

    def _stop_client_process(self, log_stopping: bool = True) -> None:
        if self.client_process and self.client_process.poll() is None:
            try:
                if log_stopping:
                    # logging.info("Attempting to terminate client process...")
                    pass
                if self.client_process.stdin:
                    try:
                        self.client_process.stdin.close()
                    except Exception:
                        pass
                # Kill client process and all children if still alive
                if self.client_process is not None and self.client_process.poll() is None:
                    try:
                        try:
                            import psutil
                            parent = psutil.Process(self.client_process.pid)
                            for child in parent.children(recursive=True):
                                child.kill()
                            parent.kill()
                        except ImportError:
                            self.client_process.kill()
                        self.client_process.wait(timeout=1)
                    except Exception:
                        pass
                if log_stopping:
                    # logging.info("Client process terminated.")
                    pass
            except subprocess.TimeoutExpired:
                if log_stopping:
                    # logging.warning("Client process did not terminate gracefully, killing...")
                    pass
                self.client_process.kill()
                self.client_process.wait()
                if log_stopping:
                    # logging.info("Client process killed.")
                    pass
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
                # logging.warning("No client process is active or already stopped.")
                pass
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
            # logging.info(f"Sent command: '{command}' to client process.")
        elif not self.client_process or self.client_process.poll() is not None:
            # logging.warning("No active client process tosend command to.")
            pass
        else:
            logging.error("Client process stdin is not available.")
    
    def _add_client_to_list(self, client_id: str) -> None:
        current_items = list(self.client_listbox.get(0, tk.END))
        if client_id not in current_items:
            self.client_listbox.insert(tk.END, client_id)
            self._update_status_bar()
            # logging.info(f"GUI: Bot {client_id} connected.")
    
    def _remove_client_from_list(self, client_id: str) -> None:
        try:
            items = list(self.client_listbox.get(0, tk.END))
            if client_id in items:
                index = items.index(client_id)
                self.client_listbox.delete(index)
                self._update_status_bar()
                # logging.info(f"GUI: Bot {client_id} disconnected.")
        except tk.TclError:
            pass

    def _display_client_output(self, source: str, message: str) -> None:
        try:
            self.client_output_text.configure(state='normal')
            if source not in self.output_lines:
                self.output_lines[source] = ""
            self.output_lines[source] += message
            if '\n' in self.output_lines[source]:
                line, rest = self.output_lines[source].split('\n', 1)
                self.client_output_text.insert(tk.END, f"[{source}]: {line}\n")
                self.output_lines[source] = rest
            self.client_output_text.see(tk.END)
            self.client_output_text.configure(state='disabled')
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
                    # --- Disable disconnect button and reset process if no clients remain ---
                    if self.client_process is not None and self.client_process.poll() is not None:
                        self.disconnect_collaborator_button.config(state=tk.DISABLED)
                        self.connect_collaborator_button.config(state=tk.NORMAL)
                        self.connect_ca_collaborator_button.config(state=tk.NORMAL)
                        self.client_process = None
                        self.client_stdin = None
                        # If no clients remain, clear the listbox
                        if self.client_listbox.size() == 0:
                            self._clear_client_listbox()
            # Process messages from the server to specific clients (if any)
            while not self.client_message_queue.empty():
                client_id, message = self.client_message_queue.get_nowait()
                self._display_client_output(client_id, message + '\n')

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
            self.root.after(100, self._process_queues)

    def _clear_all_logs(self) -> None:
        """Clear all log displays"""
        try:
            # Clear server log
            self.server_log_text.configure(state='normal')
            self.server_log_text.delete('1.0', tk.END)
            self.server_log_text.configure(state='disabled')
            # Clear client output
            self._clear_client_output_display()
            # Reset output lines dictionary to prevent old data from appearing
            for key in list(self.output_lines.keys()):
                self.output_lines[key] = ""
        except tk.TclError:
            pass
        except Exception as e:
            logging.error(f"Error clearing logs: {e}")
    
    def _clear_client_output_display(self) -> None:
        """Clear the client output text widget."""
        try:
            self.client_output_text.configure(state='normal')
            self.client_output_text.delete('1.0', tk.END)
            self.client_output_text.configure(state='disabled')
        except tk.TclError:
            pass

    def _clear_client_listbox(self) -> None:
        """Clear the Active Bots listbox."""
        try:
            self.client_listbox.delete(0, tk.END)
        except tk.TclError:
            pass

    def _on_closing(self) -> None:
        """Handles the event when the user clicks the 'X' button. Ensures all subprocesses and threads are forcefully terminated."""
        # Attempt graceful shutdown first
        self.stop_server(log_stopping=False)
        self.stop_ca_process(log_stopping=False)
        self._stop_client_process(log_stopping=False)

        # --- Force kill any remaining subprocesses ---
        import signal
        # Kill CA process if still alive
        if self.ca_process is not None and self.ca_process.poll() is None:
            try:
                self.ca_process.kill()
                self.ca_process.wait(timeout=1)
            except Exception:
                pass
            self.ca_process = None
        # Kill client process if still alive
        if self.client_process is not None and self.client_process.poll() is None:
            try:
                # Kill client process and all children if still alive
                if self.client_process is not None and self.client_process.poll() is None:
                    try:
                        try:
                            import psutil
                            parent = psutil.Process(self.client_process.pid)
                            for child in parent.children(recursive=True):
                                child.kill()
                            parent.kill()
                        except ImportError:
                            self.client_process.kill()
                        self.client_process.wait(timeout=1)
                    except Exception:
                        pass
            except Exception:
                pass
            self.client_process = None
        # Force kill server thread if still alive (Windows only: forcibly terminate process)
        if self.server_thread is not None and self.server_thread.is_alive():
            try:
                import ctypes
                tid = self.server_thread.ident
                if tid is not None:
                    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(SystemExit))
            except Exception:
                pass
            self.server_thread = None
        # Destroy GUI
        self.root.destroy()

    def _update_mission_timer(self) -> None:
        """Update the mission timer display"""
        try:
            import time
            elapsed = time.time() - self.mission_start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            self.mission_time_label.config(text=f"⏱️ Mission Time: {hours:02d}:{minutes:02d}:{seconds:02d}")
            self.root.after(1000, self._update_mission_timer)
        except Exception:
            pass

    def _update_status_bar(self) -> None:
        """Update the status bar with current system state"""
        try:
            # Check server status
            server_status = "🟢 Online" if (self.server_thread and self.server_thread.is_alive()) else "🔴 Offline"
            
            # Check CA status  
            ca_status = "🟢 Online" if (self.ca_process and self.ca_process.poll() is None) else "🔴 Offline"
              # Count connected bots
            bot_count = self.client_listbox.size()
            
            status_text = f"Drone Core: {server_status} | CA: {ca_status} | Bots: {bot_count} Connected"
            self.status_label.config(text=status_text)
        except Exception:
            pass

    def _ask_proxy_preference(self) -> bool:
        """Prompt the user to choose whether to use a proxy connection."""
        import tkinter.simpledialog
        answer = tkinter.simpledialog.askstring(
            "🔧 Operation BLACKBIRD - Proxy Configuration",
            "Configure proxy tunnel for secure communications?\n\n" +
            "📡 This will route traffic through your configured proxy\n" +
            "🔒 Required for certain mission parameters\n\n" +
            "Enter 'yes' to enable proxy tunnel (yes/no):",
            parent=self.root
        )
        if answer and answer.strip().lower() in ("yes", "y"): 
            return True
        return False

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

def main() -> None:
    """Main entry point for GUI application."""
    import tkinter as tk
    
    root = tk.Tk()
    app = CTFGui(root)
    root.protocol("WM_DELETE_WINDOW", app._on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
    # Clean up on exit