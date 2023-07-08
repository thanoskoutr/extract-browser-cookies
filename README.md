# Cookies

This program attempts to read the stored cookies on the current user's browser. Its functionality is similar to `mimikatz` on Windows.

## Firefox

TODO:

## Google Chrome / Chromium

### Sqlite Database

Chrome and Chromium store their cookies in the `Cookies` sqlite3 Database that is under specific location for each operating system.

Cookies Database:

- Chrome (> Version 96):
  - Windows:
    - Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies`
    - Chrome Beta: `%LOCALAPPDATA%\Google\Chrome Beta\User Data\Default\Network\Cookies`
    - Chrome Canary: `%LOCALAPPDATA%\Google\Chrome SxS\User Data\Default\Network\Cookies`
    - Chromium: `%LOCALAPPDATA%\Chromium\User Data\Default\Network\Cookies`
  - Linux:
    - Chrome Stable: `~/.config/google-chrome/Default/Network/Cookies`
    - Chrome Beta: `~/.config/google-chrome-beta/Default/Network/Cookies`
    - Chrome Dev:` ~/.config/google-chrome-unstable/Default/Network/Cookies`
    - Chromium: `~/.config/chromium/Default/Network/Cookies`
- Chrome (< Version 96):
  - Windows:
    - Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`
    - Chrome Beta: `%LOCALAPPDATA%\Google\Chrome Beta\User Data\Default\Cookies`
    - Chrome Canary: `%LOCALAPPDATA%\Google\Chrome SxS\User Data\Default\Cookies`
    - Chromium: `%LOCALAPPDATA%\Chromium\User Data\Default\Cookies`
  - Linux:
    - Chrome Stable: `~/.config/google-chrome/Default/Cookies`
    - Chrome Beta: `~/.config/google-chrome-beta/Default/Cookies`
    - Chrome Dev:` ~/.config/google-chrome-unstable/Default/Cookies`
    - Chromium: `~/.config/chromium/Default/Cookies`

Linux (snap): `~/snap/chromium/common/chromium/Default`

- [Chromium Docs - User Data Directory](https://chromium.googlesource.com/chromium/src/+/master/docs/user_data_dir.md)
- [Cookies Database Moving in Chrome 96](https://dfir.blog/cookies-database-moving-in-chrome-96/)

### Encryption

Starting from version 80 of Chrome and other Chromium-based web browsers, the cookies and Web site passwords stored by the Web browser are encrypted in completely different way.
In previous versions, the cookies and passwords were encrypted by using the DPAPI encryption system of Windows.
In the new version of Chrome/Chromium, cookies and passwords are encrypted using the AES256-GCM algorithm, and the AES encryption key is encrypted with the DPAPI encryption system, and the encrypted key is stored inside the ‘Local State’ file.

- Chrome:

  - Windows (Chrome Version > 80):
    - Description 1: Cookies and passwords are encrypted using the AES256-GCM algorithm, and the AES encryption key is encrypted with the DPAPI encryption system, and the encrypted key is stored inside the `User Data/Local State` file.
    - Description 2: On Windows, Chrome uses the Data Protection API (DPAPI) to bind your passwords to your user account and store them on disk encrypted with a key only accessible to processes running as the same logged on user.
    - Encryption Algorithm: `AES_256_GCM`
    - Encryption Key storage: DPAPI
  - Windows (Chrome Version < 80):
    - Description: Cookies and passwords are encrypted by using the DPAPI encryption system of Windows.
    - Encryption Algorithm: DPAPI
    - Encryption Key storage: _None_
  - Linux (Chrome Version > 50):
    - Description: On Linux Chrome stores the credentials in `Login Data` in the Chrome user’s profile directory, but encrypted on disk with a key that is then stored in the user's Gnome Keyring or KWallet. If there is no available Keyring or KWallet, the data is not encrypted when stored.
    - Encryption Algorithm: `AES_128_CBC`
    - Encryption Key storage: Gnome Keyring or KWallet
  - Linux (Chrome Version > 50):
    - Description: On Linux Chrome stores credentials directly in the user‘s Gnome Keyring or KWallet.
    - Encryption Algorithm: Gnome Keyring or KWallet
    - Encryption Key storage: _None_

Key decryption is possible for the current logged in user. Other users cannot decrypt it, but any malware or attacker that has access to the machine can.

- [Chromium - DPAPI inside the sandbox (public version)](https://docs.google.com/document/d/11rp7qkTYGythyKgjvmmkII9wySvXkM9uYM6cPmchJ1U/edit)
- [Local Data Encryption in Chromium](https://textslashplain.com/2020/09/28/local-data-encryption-in-chromium/)
- [Chromium Google Source - components/os_crypt/os_crypt_linux.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/components/os_crypt/os_crypt_linux.cc)
- [Chromium Google Source - components/os_crypt/os_crypt_win.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/components/os_crypt/os_crypt_win.cc)
- [Chrome Security FAQ - Does the Password Manager store my passwords encrypted on disk?](https://chromium.googlesource.com/chromium/src/+/master/docs/security/faq.md#does-the-password-manager-store-my-passwords-encrypted-on-disk)
- [NirBlog - Tools update for the new encryption of Chrome / Chromium version 80](https://blog.nirsoft.net/2020/02/19/tools-update-new-encryption-chrome-chromium-version-80/)

### Implementations

Some implementations in Python that attempt to extract or use the users cookies from Chrome:

- [How to Extract Chrome Cookies in Python](https://www.thepythoncode.com/article/extract-chrome-cookies-python)
- [GitHub - n8henrie/pycookiecheat](https://github.com/n8henrie/pycookiecheat)
- [GitHub - Arnie97/chrome-cookiejar](https://github.com/Arnie97/chrome-cookiejar)

### Resources

- [RFC 6265 - HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
- [RFC 6265bis - Cookies: HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- [Chromium Google Source - net/cookies](https://chromium.googlesource.com/chromium/src/+/HEAD/net/cookies/)
- [Chromium Google Source - net/extras/sqlite/sqlite_persistent_cookie_store.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/net/extras/sqlite/sqlite_persistent_cookie_store.cc)

## MITRE ATT&CK Techniques

- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1185 - Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [T1533 - Data from Local System](https://attack.mitre.org/techniques/T1533/)

## TODO

- Add other browsers support:
  - Mozilla
  - Edge
  - Opera
- Create robust defaults:
  - Path to sqlite DBs
  - Environmental Variables
  - Encryption schemes
- Add docs:
  - In code
  - In readme
