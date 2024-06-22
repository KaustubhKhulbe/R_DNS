import subprocess
import signal
import os
import time

def start_server(enable_cache):
    try:
        # Start the server using cargo run
        server_process = subprocess.Popen(["cargo", "run", f"{str(enable_cache).lower()}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Server started successfully.")
        return server_process
    except Exception as e:
        print(f"Error starting server: {e}")
        return None
    
def stop_server(server_process):
    try:
        # Terminate the server process
        server_process.terminate()
        print("Server process terminated.")
    except Exception as e:
        print(f"Error terminating server process: {e}")

def verify_server():
    try:
        domain = "google.com"
        dig_command = ["dig", f"@127.0.0.1", "-p", "2053", domain]

        # Execute dig command and capture output
        process = subprocess.Popen(dig_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=30)  # Adjust timeout as needed
        
        # Check if dig command succeeded
        if process.returncode == 0:
            print("Response from server:")
            print(stdout.decode("utf-8"))  # Print stdout of dig command
        else:
            print(f"Error executing dig command: {stderr.decode('utf-8')}")

        return 0
        
    except Exception as e:
        print(f"Error interacting with server: {e}")
        return -1

def server_lifecycle():
    # Start the server
    server_process = start_server()
    if server_process:
        print(f"Server PID: {server_process.pid}")

        # Wait for server to start (adjust sleep duration as needed)
        print("Waiting for server to start...")
        time.sleep(4)  # Wait 10 seconds for server to initialize

        # Perform operations with the server running
        # Example: Use dig to query the server (replace with your actual interaction code)
        code = verify_server()

        # Optionally terminate the server process
        stop_server(server_process)
    else:
        print("Server failed to start.")

if __name__ == "__main__":
    server_lifecycle()