import subprocess
from colorama import Fore, init

# Inicializace colorama
init(autoreset=True)

def execute_adb_command(command):
    """Funkce pro spuštění ADB příkazu a vrácení výstupu"""
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def dump_contacts():
    """Dump kontaktů do textového souboru"""
    print(Fore.GREEN + f"Fetching contacts...")
    command = ['adb', 'shell', 'content', 'query', '--uri', 'content://contacts/phones/']
    output = execute_adb_command(command)
    
    contacts = output.splitlines()
    print(Fore.GREEN + f"Fetched {len(contacts)} contacts...")
    
    phone_number = contacts[0].split(":")[1]  # Předpokládám, že první kontakt obsahuje telefonní číslo
    with open(f"contacts_dump_{phone_number}.txt", 'w') as f:
        for contact in contacts:
            f.write(contact + "\n")
    
    print(Fore.GREEN + f"Contacts saved at > contacts_dump_{phone_number}.txt")

def send_sms(destination, text):
    """Odeslání SMS na číslo destination"""
    print(Fore.GREEN + f"Sending SMS to {destination}...")
    command = ['adb', 'shell', 'service', 'call', 'isms', '1', 's', destination, 's', text, 's', 'null']
    execute_adb_command(command)
    print(Fore.GREEN + "SMS SENT!")

def dump_sms():
    """Dump SMS zpráv do textového souboru"""
    print(Fore.GREEN + f"Fetching SMS messages...")
    command = ['adb', 'shell', 'content', 'query', '--uri', 'content://sms/']
    output = execute_adb_command(command)
    
    sms = output.splitlines()
    print(Fore.GREEN + f"Fetched {len(sms)} SMS messages...")
    
    phone_number = sms[0].split(":")[1]  # Předpokládám, že první SMS obsahuje telefonní číslo
    with open(f"sms_dump_{phone_number}.txt", 'w') as f:
        for message in sms:
            f.write(message + "\n")
    
    print(Fore.GREEN + f"SMS messages saved at > sms_dump_{phone_number}.txt")

def make_call(destination):
    """Zahájení hovoru na číslo destination"""
    print(Fore.GREEN + f"Making call to {destination}...")
    command = ['adb', 'shell', 'am', 'start', '-a', 'android.intent.action.CALL', '-d', f'tel:{destination}']
    execute_adb_command(command)
    print(Fore.GREEN + f"Call initiated to {destination}.")

def main():
    """Hlavní funkce pro zpracování příkazů"""
    print(Fore.YELLOW + "Starting HANDLER in Android mode...")

    while True:
        # Prompt pro uživatelský vstup
        command = input(Fore.MAGENTA + "metercrack > ")

        if command == "dump_contacts":
            dump_contacts()
        elif command.startswith("send_sms -d "):
            parts = command.split(" -d ")
            destination = parts[1].split(" ")[0]  # Extrahuje telefonní číslo
            text = command.split("-t ")[1]  # Extrahuje text zprávy
            send_sms(destination, text)
        elif command == "dump_sms":
            dump_sms()
        elif command.startswith("call -d "):
            destination = command.split(" -d ")[1]
            make_call(destination)
        else:
            print(Fore.RED + "Invalid command. Please try again.")

if __name__ == "__main__":
    main()
