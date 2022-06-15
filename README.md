# Password Checker - Python Script
A script that will check how many times a password has been leaked on the internet from data breaches. This is done by querying the [have i been pwned API](https://haveibeenpwned.com/API/v3).

To run:
```
python3 checkmypass.py <your-password/s>
```

Within the file there is functionality to check passwords from a text file. Just uncomment commented sections, set up passkeeper.txt and run without args:
```
python3 checkmypass.py
```
