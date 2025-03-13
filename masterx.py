import subprocess
import os
import time
from colorama import Fore, init

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
        elif command == "exit":
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid command!")

if __name__ == "__main__":
    start_handler()
