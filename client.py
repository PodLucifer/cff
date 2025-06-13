import socket
import sys
import os
import threading
import getpass
import time
from pysqlcipher3 import dbapi2 as sqlcipher
from libpx1 import DoubleRatchet, PXAddress, X3DH, SessionRecord, SessionStore

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 47890

class SQLCipherSessionStore(SessionStore):
    def __init__(self, db_path, db_pass):
        self.conn = sqlcipher.connect(db_path)
        c = self.conn.cursor()
        c.execute("PRAGMA key = '{}';".format(db_pass))
        c.execute("""CREATE TABLE IF NOT EXISTS session_records (
                        username TEXT PRIMARY KEY,
                        record BLOB
                    );""")
        c.execute("""CREATE TABLE IF NOT EXISTS skipped_keys (
                        username TEXT,
                        dh_pub BLOB,
                        n INTEGER,
                        mk BLOB,
                        PRIMARY KEY(username, dh_pub, n)
                    );""")
        self.conn.commit()

    def putSession(self, address: PXAddress, sessionRecord: SessionRecord):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO session_records (username, record) VALUES (?, ?);",
                  (address.toString(), sessionRecord.state_bytes))
        c.execute("DELETE FROM skipped_keys WHERE username=?;", (address.toString(),))
        for (dh_pub, n), mk in sessionRecord.skipped_keys.items():
            c.execute("INSERT INTO skipped_keys (username, dh_pub, n, mk) VALUES (?, ?, ?, ?);",
                      (address.toString(), dh_pub, n, mk))
        self.conn.commit()

    def getSession(self, address: PXAddress):
        c = self.conn.cursor()
        c.execute("SELECT record FROM session_records WHERE username=?;", (address.toString(),))
        row = c.fetchone()
        if not row:
            return None
        state_bytes = row[0]
        c.execute("SELECT dh_pub, n, mk FROM skipped_keys WHERE username=?;", (address.toString(),))
        skipped_keys = {}
        for dh_pub, n, mk in c.fetchall():
            skipped_keys[(dh_pub, n)] = mk
        state = DoubleRatchetState.deserialize(state_bytes)
        state.MKSKIPPED = skipped_keys
        return SessionRecord(state)

def get_database_path(username):
    idx = 1 if not os.path.exists("msgstore-1.cryptdbX") else 2
    return f"msgstore-{idx}.cryptdbX"

def receive_messages(sock):
    while True:
        data = sock.recv(4096)
        if not data:
            print("Disconnected from server.")
            os._exit(0)
        print(data.decode(), end='')

def main():
    db_pass = getpass.getpass("Enter SQLCipher DB password: ")
    username = input("Enter your username: ").strip()
    db_path = get_database_path(username)
    session_store = SQLCipherSessionStore(db_path, db_pass)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        sys.exit(1)
    # Send username for authentication
    prompt = sock.recv(128)
    print(prompt.decode(), end='')
    sock.sendall((username + '\n').encode())

    # Wait for server message about peer
    msg = sock.recv(4096).decode()
    print(msg, end='')
    if "[SYSTEM] Waiting for peer" in msg:
        msg = sock.recv(4096).decode()
        print(msg, end='')

    # Start receiving thread
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    # Chat loop
    try:
        while True:
            msg = input()
            if not msg:
                continue
            sock.sendall(msg.encode() + b'\n')
            # Store sent message in SQLCipher
            c = session_store.conn.cursor()
            c.execute("CREATE TABLE IF NOT EXISTS messages (username TEXT, msg BLOB, ts INTEGER);")
            c.execute("INSERT INTO messages (username, msg, ts) VALUES (?, ?, ?);",
                      (username, msg.encode(), int(time.time())))
            session_store.conn.commit()
    except (KeyboardInterrupt, EOFError):
        print("\nDisconnecting...")
        sock.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
