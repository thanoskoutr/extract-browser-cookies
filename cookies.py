import os
import subprocess
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome
import errno
import winreg

# TODO: Validate that browser is installed
# TODO: Add alternative sqlite file locations support
# TODO: Add alternative encryption scheme based on version/OS
# TODO: Add linux/windows support
# TODO: Add firefox/edge/opera support
# TODO: Add test


chrome_paths = {
    "windows": {
        "Google Chrome": {
            "install_path": os.path.join(os.environ.get("USERPROFILE", ""), "Google", "Chrome"),
            "cookies_path": {
                ">v96": os.path.join("User Data", "Default", "Network", "Cookies"),
                "<v96": os.path.join("User Data", "Default", "Cookies"),
            },
            "enc_key_path": {
                ">v80": os.path.join("User Data", "Local State"),
            }
        },
        "Google Chrome Beta": {
            "install_path": os.path.join(os.environ.get("USERPROFILE", ""), "Google", "Chrome Beta"),
            "cookies_path": {
                ">v96": os.path.join("User Data", "Default", "Network", "Cookies"),
                "<v96": os.path.join("User Data", "Default", "Cookies"),
            },
            "enc_key_path": {
                ">v80": os.path.join("User Data", "Local State"),
            }
        },
        "Google Chrome SxS": {
            "install_path": os.path.join(os.environ.get("USERPROFILE", ""), "Google", "Chrome SxS"),
            "cookies_path": {
                ">v96": os.path.join("User Data", "Default", "Network", "Cookies"),
                "<v96": os.path.join("User Data", "Default", "Cookies"),
            },
            "enc_key_path": {
                ">v80": os.path.join("User Data", "Local State"),
            }
        },
        "Chromium": {
            "install_path": os.path.join(os.environ.get("USERPROFILE", ""), "Chromium"),
            "cookies_path": {
                ">v96": os.path.join("User Data", "Default", "Network", "Cookies"),
                "<v96": os.path.join("User Data", "Default", "Cookies"),
            },
            "enc_key_path": {
                ">v80": os.path.join("User Data", "Local State"),
            }
        },
    },
    "linux": {
        "google-chrome": {
            "install_path": os.path.join(os.environ.get("HOME", "~"), ".config", "google-chrome"),
            "cookies_path": {
                ">v96": os.path.join("Default", "Network", "Cookies"),
                "<v96": os.path.join("Default", "Cookies"),
            }
        },
        "google-chrome-beta": {
            "install_path": os.path.join(os.environ.get("HOME", "~"), ".config", "google-chrome-beta"),
            "cookies_path": {
                ">v96": os.path.join("Default", "Network", "Cookies"),
                "<v96": os.path.join("Default", "Cookies"),
            }
        },
        "google-chrome-unstable": {
            "install_path": os.path.join(os.environ.get("HOME", "~"), ".config", "google-chrome-unstable"),
            "cookies_path": {
                ">v96": os.path.join("Default", "Network", "Cookies"),
                "<v96": os.path.join("Default", "Cookies"),
            }
        },
        "chromium-browser": {
            "install_path": os.path.join(os.environ.get("HOME", "~"), ".config", "chromium"),
            "cookies_path": {
                ">v96": os.path.join("Default", "Network", "Cookies"),
                "<v96": os.path.join("Default", "Cookies"),
            }
        },
    }
}


def linux_browser_version(app):
    app_name = ""
    app_vers = ""
    # Find if provided app is installed
    if shutil.which(app) is not None:
        app_name = app
        # Get version
        process = subprocess.Popen(
            [app, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        # Return last part that contains only the version number
        if process.returncode == 0:
            # TODO: Fix version fetching
            app_vers = out.decode().split()[-1]
    return app_name, app_vers


def win_app_version(app):
    app_name = ""
    app_vers = ""
    # Windows Arch versions
    proc_arch = os.environ.get('PROCESSOR_ARCHITECTURE', '').lower()
    proc_arch64 = os.environ.get('PROCESSOR_ARCHITEW6432', '').lower()

    # Define Windows arch to set correct registry key
    if proc_arch == 'x86' and not proc_arch64:
        arch_keys = {0}
    elif proc_arch == 'x86' or proc_arch == 'amd64':
        arch_keys = {winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY}
    else:
        raise Exception("Unhandled arch: %s" % proc_arch)

    for arch_key in arch_keys:
        # Open the desired registry key with the default access rights for each arch
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | arch_key)
        # Search to find the key with the desired app name
        for i in range(0, winreg.QueryInfoKey(key)[0]):
            skey_name = winreg.EnumKey(key, i)
            skey = winreg.OpenKey(key, skey_name)
            try:
                disp_name = winreg.QueryValueEx(skey, 'DisplayName')[0]
                # Return the app name and version found
                if app in disp_name:
                    app_name = disp_name
                    app_vers = winreg.QueryValueEx(skey, 'DisplayVersion')[0]
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # DisplayName doesn't exist in this skey
                    pass
            finally:
                skey.Close()
    return app_name, app_vers


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""


def get_encryption_key():
    local_state_path = os.path.join(
        os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    # JSON file
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove 'DPAPI' prefix string
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def main():
    # local sqlite Chrome cookie database path for WINDOWS (7-10)
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    # local sqlite Chrome cookie database path for WINDOWS (XP)
    # db_path = os.path.join(os.environ["USERPROFILE"], "Local Settings", "Application Data", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    # local sqlite Chrome cookie database path for LINUX (Chrome)
    # db_path = os.path.join(os.environ["USER"], ".config", "google-chrome", "User Data", "Default", "Network", "Cookies")
    # local sqlite Chrome cookie database path for LINUX (Chromium)
    # db_path = os.path.join(os.environ["USER"], ".config", "chromium", "User Data", "Default", "Network", "Cookies")

    # copy the file to current directory as the database will be locked if chrome is currently open
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        # copy file when does not exist in the current directory
        shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # get the cookies from `cookies` table
    # More info about the database: [Google Chrome Forensics](https://www.sans.org/blog/google-chrome-forensics/)
    cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    FROM cookies""")
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%twitter.com%'""")

    # results = cursor.fetchall()
    # for r in results:
    #     print(r)
    # get the AES key

    key = get_encryption_key()
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        # if not value:
        #     decrypted_value = decrypt_data(encrypted_value, key)
        # else:
        #     # already decrypted
        #     decrypted_value = value
        # decrypted_value = value
        decrypted_value = decrypt_data(encrypted_value, key)
        print(f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value:             {value}
        Cookie value (encrypted): {encrypted_value}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================""")
        # update the cookies table with the decrypted value
        # and make session cookie persistent
        # cursor.execute("""
        # UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        # WHERE host_key = ?
        # AND name = ?""", (decrypted_value, host_key, name))
    # commit changes
    db.commit()
    # close connection
    db.close()


if __name__ == "__main__":
    name, version = win_app_version("Google Chrome")
    print(name, version)
    name, version = win_app_version("Chromium")
    print(name, version)
    name, version = linux_browser_version("google-chrome")
    print(name, version)
    name, version = linux_browser_version("chromium-browser")
    print(name, version)
    main()
