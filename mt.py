import os
import json
import subprocess
import platform
from colorama import Fore, Style, init

init(autoreset=True)

def run_adb_command(command):
    """Executes an ADB command and returns the output."""
    result = subprocess.run(f"adb {command}", shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def check_device():
    """Check if any device is connected."""
    devices = run_adb_command("devices")
    if "device" in devices and "list" not in devices:
        return True
    return False

def dump_contacts():
    """Dump contacts and save in a formatted JSON file."""
    contacts_raw = run_adb_command("shell content query --uri content://contacts/phones/")
    contacts = contacts_raw.split("\n") if contacts_raw else []
    contact_list = []
    for contact in contacts:
        fields = {kv.split("=")[0]: kv.split("=")[1] for kv in contact.split(" ") if "=" in kv}
        contact_list.append(fields)
    
    with open("contacts_dump.json", "w") as f:
        json.dump(contact_list, f, indent=4)
    
    print(f"{Fore.GREEN}Fetching {len(contact_list)} contacts...")
    print(f"{Fore.YELLOW}Contacts saved at > contacts_dump.json")

def dump_sms():
    """Dump SMS messages and save in a formatted JSON file."""
    sms_raw = run_adb_command("shell content query --uri content://sms/")
    sms_messages = sms_raw.split("\n") if sms_raw else []
    sms_list = []
    for sms in sms_messages:
        fields = {kv.split("=")[0]: kv.split("=")[1] for kv in sms.split(" ") if "=" in kv}
        sms_list.append(fields)
    
    with open("sms_dump.json", "w") as f:
        json.dump(sms_list, f, indent=4)
    
    print(f"{Fore.GREEN}Fetching {len(sms_list)} SMS messages...")
    print(f"{Fore.YELLOW}SMS saved at > sms_dump.json")

def call_destination(destination):
    """Make a call to a specific destination."""
    run_adb_command(f"shell am start -a android.intent.action.CALL -d tel:{destination}")
    print(f"{Fore.CYAN}Calling {destination}...")

def screen_snap():
    """Take a screenshot and save it on the server."""
    run_adb_command("shell screencap -p /sdcard/screen.png")
    run_adb_command("pull /sdcard/screen.png")
    run_adb_command("shell rm /sdcard/screen.png")
    print(f"{Fore.BLUE}Screenshot saved as screen.png")

def webcam_snap():
    """Capture an image from the webcam."""
    run_adb_command("shell input keyevent KEYCODE_CAMERA")
    run_adb_command("shell screencap -p /sdcard/webcam_snap.png")
    run_adb_command("pull /sdcard/webcam_snap.png")
    run_adb_command("shell rm /sdcard/webcam_snap.png")
    print(f"{Fore.BLUE}Webcam snapshot saved as target.png")

def upload_file(file, destination):
    """Upload a file to a specified destination."""
    run_adb_command(f"push {file} {destination}")
    print(f"{Fore.MAGENTA}Uploaded {file} to {destination}")

def webcam_list():
    """List available webcams on the device."""
    output = run_adb_command("shell ls /dev/video*")
    webcams = output.split("\n") if output else []
    print(f"{Fore.YELLOW}Found {len(webcams)} webcams:")
    for cam in webcams:
        print(f"{Fore.CYAN}{cam}")

def main():
    print(f"{Fore.RED}Starting HANDLER in Android mode...")
    if check_device():
        print(f"{Fore.GREEN}A CLIENT CONNECTED ({platform.system()})!")
    
    while True:
        try:
            command = input(f"{Fore.YELLOW}metercrack > {Style.RESET_ALL}").strip()
            if not command:
                continue
            
            parts = command.split(" ")
            cmd = parts[0]
            args = parts[1:]
            
            if cmd == "dump_contacts":
                dump_contacts()
            elif cmd == "dump_sms":
                dump_sms()
            elif cmd == "call" and "-d" in args:
                index = args.index("-d")
                call_destination(args[index + 1])
            elif cmd == "screen_snap":
                screen_snap()
            elif cmd == "webcam_snap":
                webcam_snap()
            elif cmd == "upload" and "-d" in args:
                index = args.index("-d")
                upload_file(args[0], args[index + 1])
            elif cmd == "webcam_list":
                webcam_list()
            elif cmd in ["exit", "quit"]:
                print(f"{Fore.RED}Exiting...")
                break
            else:
                print(f"{Fore.RED}Unknown command!")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")

if __name__ == "__main__":
    main()
