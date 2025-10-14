# config.py

VERSION="v1.2.1"

SERVER_HOST = '127.0.0.1'
PORT = 51337
BUFFER_SIZE = 8192*2 # Max size for single message. Keep in mind for very long lists.
HDC_COMMAND = 'hdc'

# ASCII Art for initial run: Rising sun between mountains with "Harm0nyz3r"
HARMONYZER_ASCII = f"""
            .-----.
           /       \\
          /_________\\
         / /\\  /\\  /\\ \\
        / /  \\/  \\/  \\ \\
       /_/____\\____\\___\\
      ^^^^^^^^^^^^^^^^^^^
   |\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/|
   |  H A R M 0 N Y Z 3 R |
   |______________________|

    App Security Companion Script

    {VERSION}
"""