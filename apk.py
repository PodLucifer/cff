import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW
import json
import bcrypt
import os
from datetime import datetime, timedelta
from supabase import create_client, Client
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import base64

# Supabase Setup
SUPABASE_URL = 'https://mcsqjznczjhjstkpquxa.supabase.co'
SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1jc3Fqem5jempoanN0a3BxdXhhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzgzNDU1MDksImV4cCI6MjA1MzkyMTUwOX0.Lv9SbVrngs6flfS0yBHFShOIAvECdiwHzaSddcHDXB4'
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Constants
INACTIVITY_TIMEOUT = timedelta(minutes=5)
USER_DATA_FILE = "user_data.json"
BANK_ADDRESS = "123-3816330217/0100"

# Local Storage for Username
def save_user_data(username):
    with open(USER_DATA_FILE, "w") as f:
        json.dump({"username": username}, f)

def load_user_data():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f).get("username", "")
    return ""

# Encrypt Password
def encrypt_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Generate PDF Statement
def generate_pdf_statement(user):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.drawString(100, height - 100, f"Transaction Statement for {user['pseudonym']}")
    c.drawString(100, height - 120, f"Wallet: {user['wallet']}")
    c.drawString(100, height - 140, f"Balance: {user['balance']} DMC")

    transactions = user.get('transactions', [])
    y = height - 160
    for transaction in transactions:
        c.drawString(100, y, f"{transaction['date']}: {transaction['type']} {transaction['amount']} - {transaction['description']}")
        y -= 20
        if y < 40:
            c.showPage()
            y = height - 40

    c.showPage()
    c.save()
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode()

class CryptoApp(toga.App):
    def startup(self):
        self.main_box = toga.Box(style=Pack(direction=COLUMN))

        # Login Page
        self.username_input = toga.TextInput(initial=load_user_data(), placeholder='Enter Username')
        self.password_input = toga.PasswordInput()
        self.login_button = toga.Button('Login', on_press=self.login)

        self.main_box.add(self.username_input)
        self.main_box.add(self.password_input)
        self.main_box.add(self.login_button)
        
        self.main_window = toga.MainWindow(title='DemonCoin Wallet')
        self.main_window.content = self.main_box
        self.main_window.show()

    def login(self, widget):
        username = self.username_input.value
        password = self.password_input.value
        
        user = supabase.table('users').select("*").eq('pseudonym', username).execute()
        if user.data and verify_password(password, user.data[0]['password']):
            save_user_data(username)
            self.show_dashboard(user.data[0])
        else:
            self.username_input.value = "Login Failed"

    def show_dashboard(self, user):
        self.main_box.children.clear()
        self.main_box.add(toga.Label(f"Welcome, {user['pseudonym']}!"))
        self.main_box.add(toga.Label(f"Balance: {user['balance']} DMC"))
        
        buy_button = toga.Button('Buy Crypto', on_press=lambda x: self.buy_crypto(user))
        transfer_button = toga.Button('Transfer', on_press=lambda x: self.transfer(user))
        pdf_button = toga.Button('Download Statement', on_press=lambda x: self.download_pdf(user))
        transactions_button = toga.Button('Transactions', on_press=lambda x: self.show_transactions(user))
        logout_button = toga.Button('Logout', on_press=self.logout)
        
        self.main_box.add(buy_button)
        self.main_box.add(transfer_button)
        self.main_box.add(pdf_button)
        self.main_box.add(transactions_button)
        self.main_box.add(logout_button)

    def show_transactions(self, user):
        self.main_box.children.clear()
        self.main_box.add(toga.Label("Transaction History"))

        transactions = user.get('transactions', [])
        for transaction in transactions:
            if transaction['type'] == 'revenue':
                transaction_label = toga.Label(f"+{transaction['amount']} DMC", style=Pack(color="green", font_size=18, padding=5, border_radius=10))
            else:
                transaction_label = toga.Label(f"-{transaction['amount']} DMC", style=Pack(color="red", font_size=18, padding=5, border_radius=10))

            self.main_box.add(transaction_label)
        
        back_button = toga.Button('Back', on_press=lambda x: self.show_dashboard(user))
        self.main_box.add(back_button)

    def buy_crypto(self, user):
        self.main_box.children.clear()
        variable_symbol = user.get('variable_symbol', 'default_variable_symbol')
        self.main_box.add(toga.Label("To buy your DemonCoins you must send in your mobile app an amount with your variable symbol. Your DemonCoins will appear in less than 30 minutes."))
        self.main_box.add(toga.Label(f"Bank Address: {BANK_ADDRESS}"))
        self.main_box.add(toga.Label(f"Variable Symbol: {variable_symbol}"))
        back_button = toga.Button('Back', on_press=lambda x: self.show_dashboard(user))
        self.main_box.add(back_button)

    def transfer(self, user):
        self.main_box.children.clear()
        recipient_wallet_input = toga.TextInput(placeholder='Recipient Wallet')
        amount_input = toga.TextInput(placeholder='Amount')
        description_input = toga.TextInput(placeholder='Description')
        send_button = toga.Button('Send', on_press=lambda x: self.process_transfer(user, recipient_wallet_input.value, amount_input.value, description_input.value))
        back_button = toga.Button('Back', on_press=lambda x: self.show_dashboard(user))

        self.main_box.add(recipient_wallet_input)
        self.main_box.add(amount_input)
        self.main_box.add(description_input)
        self.main_box.add(send_button)
        self.main_box.add(back_button)

    def process_transfer(self, user, recipient_wallet, amount, description):
        amount = float(amount)
        
        if recipient_wallet == user['wallet']:
            self.main_box.add(toga.Label("You cannot send to your own wallet!"))
            return
        
        if user['balance'] < amount:
            self.main_box.add(toga.Label("Insufficient balance!"))
            return
        
        recipient = supabase.table('users').select("*").eq('wallet', recipient_wallet).execute().data
        if not recipient:
            self.main_box.add(toga.Label("Recipient not found!"))
            return

        new_balance = user['balance'] - amount
        supabase.table('users').update({'balance': new_balance}).eq('user_id', user['user_id']).execute()
        self.show_dashboard(user)

    def download_pdf(self, user):
        pdf_data = generate_pdf_statement(user)
        with open("statement.pdf", "wb") as f:
            f.write(base64.b64decode(pdf_data))

    def logout(self, widget):
        self.startup()

if __name__ == '__main__':
    CryptoApp('demoncoin-wallet', 'org.demoncoin.wallet').main_loop()
