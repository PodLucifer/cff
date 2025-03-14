import os
import subprocess
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def execute_adb_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8'), result.stderr.decode('utf-8')

def dump_contacts():
    print(Fore.GREEN + "Fetching contacts...")
    output, error = execute_adb_command("adb shell content query --uri content://contacts/phones/ --projection display_name:number")
    contacts = output.splitlines()
    print(Fore.GREEN + f"Fetched {len(contacts)} contacts...")
    with open("contacts_dump.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(contacts))
    print(Fore.GREEN + "Contacts saved at > contacts_dump.txt")

def dump_sms():
    print(Fore.GREEN + "Fetching SMS messages...")
    output, error = execute_adb_command("adb shell content query --uri content://sms/")
    sms = output.splitlines()
    print(Fore.GREEN + f"Fetched {len(sms)} SMS messages...")
    with open("sms_dump.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(sms))
    print(Fore.GREEN + "SMS saved at > sms_dump.txt")

def call(destination):
    execute_adb_command(f"adb shell am start -a android.intent.action.CALL -d tel:{destination}")
    print(Fore.GREEN + f"Calling {destination}...")

def screen_snap():
    execute_adb_command("adb exec-out screencap -p > screen_snap.png")
    print(Fore.GREEN + "Screen snapshot saved as screen_snap.png")

def webcam_snap():
    execute_adb_command("adb exec-out screencap -p > webcam_snap.png")
    print(Fore.GREEN + "Webcam snapshot saved as webcam_snap.png")

def upload_file(file, destination):
    execute_adb_command(f"adb push {file} {destination}")
    print(Fore.GREEN + f"File {file} uploaded to {destination}")

def webcam_list():
    output, error = execute_adb_command("adb shell 'ls /dev/video*'")
    webcams = output.splitlines()
    print(Fore.GREEN + f"Found {len(webcams)} webcams: {', '.join(webcams)}")

def start_handler():
    print(Fore.YELLOW + "Starting TCP HANDLER in Android mode...")
    while True:
        input_command = input(Fore.CYAN + "metercrack > ").strip()
        if input_command.startswith("dump_contacts"):
            dump_contacts()
        elif input_command.startswith("dump_sms"):
            dump_sms()
        elif input_command.startswith("call -d"):
            destination = input_command.split(" ")[2]
            call(destination)
        elif input_command.startswith("screen_snap"):
            screen_snap()
        elif input_command.startswith("webcam_snap"):
            webcam_snap()
        elif input_command.startswith("upload"):
            parts = input_command.split(" ")
            file = parts[1]
            destination = parts[3]
            upload_file(file, destination)
        elif input_command.startswith("webcam_list"):
            webcam_list()
        else:
            print(Fore.RED + "Invalid command")

if __name__ == "__main__":
    start_handler()
