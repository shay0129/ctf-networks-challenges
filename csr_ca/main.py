import subprocess
import time

def start_server():
    """מפעיל את שרת CA כתהליך נפרד."""
    server_process = subprocess.Popen(['python', 'ca_server.py'])
    return server_process

def start_client():
    """מפעיל את לקוח CSR כתהליך נפרד."""
    client_process = subprocess.Popen(['python', 'csr_client.py'])
    return client_process

if __name__ == '__main__':
    server_process = start_server()
    time.sleep(1)  # המתנה קצרה לוודא שהשרת התחיל
    client_process = start_client()

    try:
        # אפשר לתהליכים לרוץ עד שיסתיימו או שתקבל KeyboardInterrupt
        server_process.wait()
        client_process.wait()
    except KeyboardInterrupt:
        print("\nהפעלה הופסקה על ידי המשתמש.")
        server_process.terminate()
        client_process.terminate()
        server_process.wait()
        client_process.wait()
    except Exception as e:
        print(f"שגיאה: {e}")
        server_process.terminate()
        client_process.terminate()
        server_process.wait()
        client_process.wait()