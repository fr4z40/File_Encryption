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

class AES_File_Encryption(object):

    '''
    Encryption and Decryption files using AES-256.

    Use:
        AES_File_Encryption(mode, key, path_input, path_ouput, iv_size)

    Log the output (As a "DICT" type):
        log = AES_File_Encryption(mode, key, path_input, path_ouput, iv_size).DATA


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

    * iv_size = Optional, if not set
        If not seted, the default "AES.block_size"(16bits) will be used.
    '''

    from Crypto.Cipher import AES
    from Crypto import Random
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


    def encrypt_file(self, key, path_input, path_ouput, iv_size):

        path_input = path_input.strip()

        # Initialization Vector using random block with 16 bits (default, except if pass a new size)
        iv = self.Random.new().read(iv_size)

        # Creating the AES object "aes_obj", with mode "CBC"
        aes_obj = self.AES.new(key, self.AES.MODE_CBC, iv)

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
        cipher = aes_obj.encrypt(fl_in_content)
        out = iv+cipher
        fl_out.write(out)
        fl_out.close()

        self.DATA['size_out'] = self.Path.getsize(path_ouput)


    def decrypt_file(self, key, path_input, path_ouput, iv_size):

        path_input = path_input.strip()
        fl_in = open(path_input, 'rb')
        fl_in_content = fl_in.read()
        fl_in.close()

        # Getting the "Initialization Vector"
        iv = fl_in_content[:iv_size]

        # Creating the object, to perform the decryption
        aes_obj = self.AES.new(key, self.AES.MODE_CBC, iv)

        rst = ((aes_obj.decrypt(fl_in_content))[iv_size:]).strip(b'\x00')

        fl_out = open(path_ouput, 'wb')
        fl_out.write(rst)
        fl_out.close()

        self.DATA['size_in'] = self.Path.getsize(path_input)
        self.DATA['size_out'] = self.Path.getsize(path_ouput)


    def __init__(self, mode, key, path_input, path_ouput=None, iv_size=None):

        if not path_ouput:
            path_ouput = path_input+'.'+mode+'ed'
        if not iv_size:
            iv_size = self.AES.block_size

        self.DATA = {'input':path_input, 'output':path_ouput}

        if mode == 'encrypt':
            self.DATA['action'] = (mode+'ed').title()
            self.encrypt_file(self.key_gen(key), path_input, path_ouput, iv_size)
        else:
            self.DATA['action'] = (mode+'ed').title()
            self.decrypt_file(self.key_gen(key), path_input, path_ouput, iv_size)

