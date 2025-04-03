import random
import time

# Simulating network data
networks = [
    {"BSSID": "00:11:22:33:44:55", "PWR": -60, "Beacons": 100, "Data": 200, "Channel": 6, "MB": 54, "ENC": "WPA2", "CIPHER": "CCMP", "AUTH": "PSK", "ESSID": "MyNetwork", "STATIONS": [
        {"MAC": "00:AA:BB:CC:DD:EE", "PWR": -60, "Rate": "0 - 1", "Lost": 0, "Frames": 10, "Probe": ""},
        {"MAC": "00:FF:EE:DD:CC:BB", "PWR": -70, "Rate": "1 - 1", "Lost": 0, "Frames": 20, "Probe": ""}
    ]},
    {"BSSID": "66:77:88:99:AA:BB", "PWR": -80, "Beacons": 50, "Data": 30, "Channel": 6, "MB": 11, "ENC": "WEP", "CIPHER": "WEP", "AUTH": "OPN", "ESSID": "AnotherNet", "STATIONS": [
        {"MAC": "00:11:22:33:44:55", "PWR": -80, "Rate": "0 - 1", "Lost": 0, "Frames": 5, "Probe": "MyNetwork"}
    ]}
]

# Simulate the output
def print_network_info():
    print(f"{'BSSID':<20} {'PWR':<5} {'Beacons':<8} {'#Data, #/s':<12} {'CH':<3} {'MB':<3} {'ENC':<5} {'CIPHER':<6} {'AUTH':<4} {'ESSID':<15}")
    print("-" * 85)

    for network in networks:
        print(f"{network['BSSID']:<20} {network['PWR']:<5} {network['Beacons']:<8} {network['Data']:<6} {0:<3} {network['Channel']:<3} {network['MB']:<3} {network['ENC']:<5} {network['CIPHER']:<6} {network['AUTH']:<4} {network['ESSID']:<15}")

    print(f"\n{'BSSID':<20} {'STATION':<20} {'PWR':<5} {'Rate':<6} {'Lost':<5} {'Frames':<7} {'Probe':<6}")
    print("-" * 70)

    for network in networks:
        for station in network["STATIONS"]:
            print(f"{network['BSSID']:<20} {station['MAC']:<20} {station['PWR']:<5} {station['Rate']:<6} {station['Lost']:<5} {station['Frames']:<7} {station['Probe']:<6}")

# Simulate continuous output like in airodump-ng
def simulate_output():
    while True:
        print_network_info()
        time.sleep(5)
        print("\n" + "-" * 70 + "\n")

if __name__ == "__main__":
    simulate_output()
