# DictionaryAttack

OSCP Project: Bash scripting tool to perform dictionary attacks.

The script receives two arguments:
 - The first argument is the path to the hashes file, one per line, in sha256 hash format.
 - The second argument is a file that acts as a dictionary of words or passwords, one per line.

This script reads the plaintext words from the password dictionary, and for each of them, hashes the text string (without line breaks) and compares with each of the hashes if there is a match. It terminates when the entire password dictionary file has been read. Finally it dumps all the matches found.
