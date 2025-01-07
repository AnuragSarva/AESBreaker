# Project is basd on AES
# Part 2 of the project 

# Note :- this program will take few second to the code.

import os
import sys
# here i am importing all the necessary inbuild class and module which is present in the pyhton library
# from the cryptography library for symmeteric encryption.
# here i am using the, Cipher so that i can creat to cipher objects for the process of encryption and decryption
# here i am using the, algorithms that helps me to provide the access of various symmeteric encryption algorithm
# and also here i am using the, modes that offers me the different mode of operations for the algorithm.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# this functio helps me to adding the directory of aesLongKeyGen16.py by uisng the path 
def adding_the_script_dirct_to_the_path():
    global tnc
    scrip_itt_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(scrip_itt_dir)


# this functio is for to import the expandKey 
def import_ing_expand_ded_key():
    global tnc
    try:
        from aesLongKeyGen16 import expandKey
        return expandKey
    except:
        print("Error to find this aesLongKeyGen16 module...")

# the below function is for AES encryption 
def aes_encript_tion(mesg_sages_by_te_s, cipr_txt_s):
    global tnc
    encryp_tor_s = cipr_txt_s.encryptor()
    y = encryp_tor_s.update(mesg_sages_by_te_s)
    x = y + encryp_tor_s.finalize()
    return x


# this function is the AES decryption 
def aes_decypt_tion(cpher_txt_s, ciphr_txt_s):
    global tnc
    decryp_tor_s = ciphr_txt_s.decryptor()
    x = decryp_tor_s.update(cpher_txt_s)
    y = x + decryp_tor_s.finalize()
    return y


# the below function helps to generate all the possible intermediate value for the encryption
def gen_ration_encrypt_tion_diect(pln_txt_s, expd_and_ding_key_func_tn, iv):
    encrpt_ypt_tion_dict = {}
    global tnc
    for k_e_y_1 in range(2**16):
        # here i am converting the 2 byte key
        short_est_key_wob_1 = k_e_y_1.to_bytes(2, 'big')  
        long_est_key_wob_1 = expd_and_ding_key_func_tn(short_est_key_wob_1) 
        z = algorithms.AES(long_est_key_wob_1)
        c_pher_txt_1 = Cipher(z, modes.CBC(iv))

        y = c_pher_txt_1
        # here ,i am encrypting the first plaintext with the first key
        int_inter_me_diate = aes_encript_tion(pln_txt_s[0], y)
        # now here i am trying to mapping the intermediate to the shorter_key1
        ghi = short_est_key_wob_1
        encrpt_ypt_tion_dict[int_inter_me_diate] = ghi  

    x = encrpt_ypt_tion_dict
    return x


# the function is tryin a Brute force approach to find the second key match
def brute_force_appraoch_for_the_second_key(ciphr_txt_ss, encrypt_tion_s_dict, exp_ing_and_key_func_tn, iv):
    global tnc
    for k_e_y_2 in range(2**16):
        short_est_key_wob_2 = k_e_y_2.to_bytes(2, 'big')  
        long_est_key_wob_2 = exp_ing_and_key_func_tn(short_est_key_wob_2) 
        
        ciph_er_txt_2 = Cipher(algorithms.AES(long_est_key_wob_2), modes.CBC(iv))

        # here i am trying to decrypting the first ciphertext with the help of second key
        intermid_ate_s = aes_decypt_tion(ciphr_txt_ss[0], ciph_er_txt_2)

        # here i  am checking if the intermediate value are matche with the any value in the dictionary
        if intermid_ate_s in encrypt_tion_s_dict:
            return short_est_key_wob_2, intermid_ate_s
    
    return None, None


# the below function helps me to verify or check the key and decrypting the secret plaintext
def veri_fying_and_decryp_tion(ciphr_txt_ss, short_est_key_wob_1, short_est_key_wob_2, intermediate, expand_ded_key_func_tion, iv):
    global tnc
    long_est_key_wob_1 = expand_ded_key_func_tion(short_est_key_wob_1)
    long_est_key_wob_2 = expand_ded_key_func_tion(short_est_key_wob_2)

    cipher_txt_s_1 = Cipher(algorithms.AES(long_est_key_wob_1), modes.CBC(iv))
    cipher_txt_s_2 = Cipher(algorithms.AES(long_est_key_wob_2), modes.CBC(iv))

    intermediate = aes_decypt_tion(ciphr_txt_ss[-1], cipher_txt_s_2)
    sec_ret_pln_text = aes_decypt_tion(intermediate, cipher_txt_s_1)
    
    return sec_ret_pln_text


# the below function helps me to perform the meet in the middle attack on the AES
def this_is_meet_in_the_middle_attack_mentioned_in_the_Qnt(plain_text_sts, ciphr_txt_ss, expand_ded_key_func_tion):
    global tnc
    # this is the iv vector which is initialized with 0
    iv = b'\0' * 16  

    encryption_dict = gen_ration_encrypt_tion_diect(plain_text_sts, expand_ded_key_func_tion, iv)

    short_key2, intermediate = brute_force_appraoch_for_the_second_key(ciphr_txt_ss, encryption_dict, expand_ded_key_func_tion, iv)

    if short_key2 and intermediate:
        short_key1 = encryption_dict[intermediate]
        print(f"i found the key's found-\n\nKey 1 - {short_key1.hex()} & Key 2 - {short_key2.hex()}\n")
        print("Given plane text are -\n")
        print("i.     Hydrodynamometer")
        print("ii.    Circumnavigation")
        print("iii.   Crystallographer")
        print("iv.    Microphotography\n")
        secret_plaintext = veri_fying_and_decryp_tion(ciphr_txt_ss, short_key1, short_key2, intermediate, expand_ded_key_func_tion, iv)
        print(f"And the secret Plaintext is here - \n\nv.     {secret_plaintext.decode('utf-8')}\n")
        
        return short_key1, short_key2, secret_plaintext
    else:
        print("Unable to find the key...")
        
        return None, None, None

# below function helps me to load teh plaintexts file by using the path of the file
# after reading the plaintext data file and then it is converted into the list of string
def load_plaintext_frm_directory(file_path_form_drict):
    global tnc
    with open(file_path_form_drict, "r") as pt_file:
        rslt = []
        for line in pt_file:
            rslt.append(line.strip().encode('utf-8'))
        return rslt


# below function helps me to load the ciphertexts file by using the path of the file
# after reading the ciphertext data file and then it is converted into the list of string
def load_ciphertexts_frm_directory(file_path_form_drict):
    with open(file_path_form_drict, "r") as f:
        rslt = []
        for ln in f:
            rslt.append(bytes.fromhex(ln.strip()))
        return rslt

# here is the main function, you can say driver function.
def main():
    global tnc
    adding_the_script_dirct_to_the_path()
    exp_nd_ded_key_func_tion = import_ing_expand_ded_key()
    print("\n# Note :- this program will take few second to run the code.\n")

    # with the help of file path, i am going to get the plaintexts and ciphertexts
    pln_txt_path_from_dicte = "/home/anurag/ACN_Work/Cryptology/Cryptology_Prog_Asgn_3/2-Key AES-128/2aesPlaintexts.txt"
    ciphr_txt_path_from_dictr = "/home/anurag/ACN_Work/Cryptology/Cryptology_Prog_Asgn_3/2-Key AES-128/2aesCiphertexts.txt"

    print("Part - 2\n")

    try:
        pln_txt_s_pt = load_plaintext_frm_directory(pln_txt_path_from_dicte)
        ciph_txt_er_texts = load_ciphertexts_frm_directory(ciphr_txt_path_from_dictr)

        this_is_meet_in_the_middle_attack_mentioned_in_the_Qnt(pln_txt_s_pt, ciph_txt_er_texts, exp_nd_ded_key_func_tion)
    except:
        print("There is error in the required files which is not found...")

if __name__ == "__main__":
    main()