#!/usr/bin/env python3
import os

# Global variables
checkbox = '\u2714'
env_user = os.getenv('USER', '')
try:
    if env_user:
        red = '\033[91m'
        green = '\033[92m'
        yellow = '\033[93m'
        blue = '\033[96m'
        gray = '\033[90m'
        reset = '\033[0m'
    else:
        red, green, yellow, blue, gray, reset = '', '', '', '', '', ''
except Exception as e:
    print(f'An error occurred while setting terminal colors: {e}')
    red, green, yellow, blue, gray, reset = '', '', '', '', '', ''
