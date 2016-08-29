# -*- coding: utf-8 -*-
#
# Copyright 2016 Eduardo Frazão ( https://github.com/fr4z40 )
#
#   Licensed under the MIT License;
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#

class Twofish_File_Encryption(object):

    '''
    Encryption and Decryption files using Twofish.

    Use:
        Twofish_File_Encryption(mode, key, path_input, path_ouput)

    Log the output (As a "DICT" type):
        log = Twofish_File_Encryption(mode, key, path_input, path_ouput).DATA


    * mode = "encrypt" or "decrypt"

    * Key = Password

    * path_input = Path to input file

    * path_ouput = Path to output file
        If not seted an output name,
        the same input name will be used,
        with "[enc/de]crypted" at the end
        e.g:
            input = some_name.txt, mode "encrypt"
            output = some_name.txt.encrypted
    '''

    from twofish import Twofish
    from os import path as Path


    @staticmethod
    def key_gen(string_in):

        from hashlib import sha256

        string_in = ((string_in.replace('\r', '')).replace('\n', ''))
        # Wy not use "strip"?
        # If you set a password with space in the end or in the begin,
        # "strip" will remove this.

        sha_key = sha256(bytes(string_in, 'utf8')).digest()
        return(sha_key)


    def encrypt_file(self, key, path_input, path_ouput):

        path_input = path_input.strip()

        # Creating the Twofish object "tf_obj"
        tf_obj = self.Twofish(key)

        # If the size of the file, isn't a multiple of 16
        # will be filled with x00
        size = self.Path.getsize(path_input)
        fill_qtd = (16-(size%16))

        self.DATA['size_in'] = size

        fl_in = open(path_input, 'rb')
        fl_in_content = fl_in.read()

        fl_in.close()

        fl_in_content += (b'\x00'*fill_qtd)

        fl_out = open(path_ouput, 'wb')

        cnt_len = len(fl_in_content)
        out = []
        for r in range(0, cnt_len, 16):
            out.append(tf_obj.encrypt(fl_in_content[r:r+16]))
        fl_out.write(b''.join(out))
        fl_out.close()

        self.DATA['size_out'] = self.Path.getsize(path_ouput)


    def decrypt_file(self, key, path_input, path_ouput):

        path_input = path_input.strip()
        fl_in = open(path_input, 'rb')
        fl_in_content = fl_in.read()
        fl_in.close()

        # Creating the Twofish object "tf_obj", to perform the decryption
        tf_obj = self.Twofish(key)

        cnt_len = len(fl_in_content)
        out = []
        for r in range(0, cnt_len, 16):
            out.append(tf_obj.decrypt(fl_in_content[r:r+16]))

        fl_out = open(path_ouput, 'wb')
        fl_out.write((b''.join(out)).strip(b'\x00'))
        fl_out.close()

        self.DATA['size_in'] = self.Path.getsize(path_input)
        self.DATA['size_out'] = self.Path.getsize(path_ouput)


    def __init__(self, mode, key, path_input, path_ouput=None):

        if not path_ouput:
            path_ouput = path_input+'.'+mode+'ed'

        self.DATA = {'input':path_input, 'output':path_ouput}

        if mode == 'encrypt':
            self.DATA['action'] = (mode+'ed').title()
            self.encrypt_file(self.key_gen(key), path_input, path_ouput)
        else:
            self.DATA['action'] = (mode+'ed').title()
            self.decrypt_file(self.key_gen(key), path_input, path_ouput)

