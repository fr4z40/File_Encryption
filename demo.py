#!/usr/bin/python3

from AES_File_Encryption import AES_File_Encryption
from Twofish_File_Encryption import Twofish_File_Encryption

try:
    import readline
except:
    pass


opt = ((input('''
[1]AES-256\t[2]Twofish\t[3]Twofish+AES256 -[ ]\b\b''')).strip())


try:
    from getpass import getpass
    key = (getpass("Password:")).strip('\n').strip('\r')
except:
    key = (input("Password:")).strip('\n').strip('\r')


file_in = (input('Input Path/Name (type or drag):')).strip()
file_in = file_in.strip('"').strip("'")


file_out = (input('[optional, hit enter to skip] Output Path/Name (type or drag):')).strip()
file_out = file_out.strip('"').strip("'")


if len(file_out) < 2:
    file_out = None


action = {'1':'encrypt', '2':'decrypt'}[(input('[1]-Encrypt\t[2]-Decrypt -[ ]\b\b')).strip()]


if opt == '1':
    AES_File_Encryption(action, key, file_in, file_out)

elif opt == '2':
    Twofish_File_Encryption(action, key, file_in, file_out)

elif opt == '3':

    if action == 'encrypt':
        log = Twofish_File_Encryption(action, key, file_in, file_out).DATA
        file_in = log['output']
        if not file_out:
            file_out = file_in
        AES_File_Encryption(action, key, file_in, file_out,)

    else:
        log = AES_File_Encryption(action, key, file_in, file_out,).DATA
        file_in = log['output']
        if not file_out:
            file_out = file_in
        Twofish_File_Encryption(action, key, file_in, file_out)

else:
    quit()

