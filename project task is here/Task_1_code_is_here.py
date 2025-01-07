# Project is Based on AES
# Part 1 of the project 

# Note :- this program will take few second to the code.

# here i am importing all the necessary inbuild class and module which is present in the pyhtin library
# from the cryptography library for symmeteric encryption.
# here i am using the, Cipher so that i can creat to cipher objects for the process of encryption and decryption
# here i am using the, algorithms that helps me to provide the access of various symmeteric encryption algorithm
# and also here i am using the, modes that offers me the different mode of operations for the algorithm.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# the below function helps to take a small size key i.e. short key and helps to expand it into the large key of 16 Bytes for the AES-128
def small_to_large_key_expansion(shrt_est_keyhihi_):
    # this helps me to extract the all individual bytes from the short size key
    # her i am taking the 1st byte of the small key 
    shrt_est_keyhihi_val1 = shrt_est_keyhihi_[0]
     # her i am taking the 2nd byte of the small key
    shrt_est_keyhihi_val2 = shrt_est_keyhihi_[1]
    # her i am taking the 3rd byte of the small key where last 4 bits are going to set to 0.
    shrt_est_keyhihi_val3 = shrt_est_keyhihi_[2] & 0xF0
    global cntnnt

    # now all the above collected vlue is convert into a single bytes of stream.
    By_t_es_C = shrt_est_keyhihi_val3.to_bytes(1, "big")
    B_yte_s_B = shrt_est_keyhihi_val2.to_bytes(1, "big")
    B_yte_s_A = shrt_est_keyhihi_val1.to_bytes(1, "big")

    # the below line of code is defination of the constant byte that helps me to used in the key expansion
    hex_B_yte_s_3 = 0xE7
    B_yte_s_3 = hex_B_yte_s_3.to_bytes(1, "big")
    hex_B_yte_s_2 = 0x5A
    Byt_est_2 = hex_B_yte_s_2.to_bytes(1, "big")
    hex_By_tes_1 = 0x94
    Byt_est_1 = hex_By_tes_1.to_bytes(1, "big")

    # here i ma start to build a long key of size 16 byte
    long_est_key_s = bytearray(B_yte_s_A)
    long_est_key_s.extend(Byt_est_1)
    long_est_key_s.extend(B_yte_s_B)
    long_est_key_s.extend(Byt_est_2)

    # after all this now i am generating the intermediate bytes that i am using for the formula which is repeat addition mod 257
    for i in range(4, 9):
        hex_by_t_es = (long_est_key_s[i - 1] + long_est_key_s[i - 4]) % 257
        if hex_by_t_es == 256:
            # it is very importatn to handle the overflow case, so below i ma try to handle that case.
            hex_by_t_es = 0  
        byte = hex_by_t_es.to_bytes(1, "big")
        long_est_key_s.extend(byte)

    # here i am adding the 3ed byte from the short key
    long_est_key_s.extend(By_t_es_C)
    long_est_key_s.extend(B_yte_s_3)

    # below line of code try to generate remaining byte
    #  here i am also uisng the same formula as usd above.
    for i in range(11, 16):
        kk = long_est_key_s[i - 1] + long_est_key_s[i - 4]
        k = (kk)
        hex_by_t_es = k % 257
        if hex_by_t_es == 256:
            # it is very importatn to handle the overflow case, so below i ma try to handle that case.
            hex_by_t_es = 0
        byte = hex_by_t_es.to_bytes(1, "big")
        long_est_key_s.extend(byte)

    return long_est_key_s

# below function helps me to load teh plaintexts file by using the path of the file
# after reading the plaintext data file and then it is converted into the list of string
def load_plaintext_frm_directory(fle_path_p):
    with open(fle_path_p, "r") as f:
        line_s = []
        for lin in f:
            line_s.append(lin.strip())
        return line_s

# below function helps me to load teh ciphertexts file by using the path of the file
# after reading the ciphertext data file and then it is converted into the list of string
def load_ciphertexts_frm_directory(fle_path_p):
    with open(fle_path_p, "r") as f:
        rslt = []
        for ln in f:
            rslt.append(bytes.fromhex(ln.strip()))
        return rslt

# the below function helps me to encrypting the plaintext by using the given key and IV value initially to 0 vector.
# the func is doing the AES encryption in the CBC mode.
def encrypting_plaintxt(pln_txt, key, iv):
    global cntnnt
    ciph_er_txt_s = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc_rypt_or = ciph_er_txt_s.encryptor()
    xyx = enc_rypt_or.update(pln_txt) + enc_rypt_or.finalize()
    return xyx

# the below function helps me to decrypt the cipheretext by using the given key and IV value initially to 0 vector.
# the func is doing the AES decryption in the CBC mode.
def decrypt_ciphertxt(ciphr_txt, key, iv):
    global cntnnt
    ciph_er_txt_s = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    dec_rypt_or = ciph_er_txt_s.decryptor() 
    x = dec_rypt_or.update(ciphr_txt) + dec_rypt_or.finalize()
    return x 

# the below function helps me to use the brute force approach for the 20 bit key space as per mentioned in the question
def brute_force_approach_to_find_the_key(plan_txt_s, ciphr_txt_s, iv):
    global cntnnt
    for shrt_est_keyhihi_ in range(2**20): 
        # this for loop helps me to iterate over all the possiblities of 20 bit keys
        # here i am generationg hte 24-bit key by using the 20 bit key by shifting it towards the left and padding it with the 0
        shrt_est_keyhihi__bytes = (shrt_est_keyhihi_ << 4).to_bytes(3, "big")
        expan_d_e_d_key = small_to_large_key_expansion(shrt_est_keyhihi__bytes)  # Expand the short key to 16 bytes

        # here i am encrypting the first plain text by using the expanded key generated above
        test_ciphertext = encrypting_plaintxt(plan_txt_s[0], expan_d_e_d_key, iv)

        if test_ciphertext == ciphr_txt_s[0]:
            return shrt_est_keyhihi__bytes, expan_d_e_d_key  # here i found the key
    return None, None 

# here is the main function, you can say driver function.
def main():
    global cntnnt
    # with the help of file path, i am going to get the plaintexts and ciphertexts
    plan_txt_path = "/home/anurag/ACN_Work/Cryptology/Cryptology_Prog_Asgn_3/AES-128/aesPlaintexts.txt"
    ciphr_txt_path = "/home/anurag/ACN_Work/Cryptology/Cryptology_Prog_Asgn_3/AES-128/aesCiphertexts.txt"

    # i am loading the plain text and the cipher texts from the file
    plan_txt_s = load_plaintext_frm_directory(plan_txt_path)
    ciphr_txt_s = load_ciphertexts_frm_directory(ciphr_txt_path)

    # below converting the plain texts into the byte format for the encryption
    plan_tex_t_bytes = []
    for p in plan_txt_s:
        plan_tex_t_bytes.append(p.encode("UTF-8"))
    print("\n# Note :- this program will take few second to run the code.\n")
    # intialising the vector iv for the CBC mode
    iv = b'\x00' * 16

    shrt_est_keyhihi__bytes, expanded_key = brute_force_approach_to_find_the_key(plan_tex_t_bytes, ciphr_txt_s, iv)
    print("Part 1 of the project.\n")

    if shrt_est_keyhihi__bytes:
        # to display the founded key as a result
        print(f"1st part, \nKey is founded - {shrt_est_keyhihi__bytes.hex()}")
        print(f"This is the key after expansan - {expanded_key.hex()}") 

        # here i ma decrypting the last most cipher text to revealing the secret plain text
        secret_ciphertext = ciphr_txt_s[-1]
        secret_plaintext = decrypt_ciphertxt(secret_ciphertext, expanded_key, iv)
        print("Given plane text are -\n")
        print("i.   Counterclockwise")
        print("ii.  sonicthehedgehog")
        print("iii. TheDeterminantor")
        print("iv.  FeedbackRegister\n")
        print(f"And the secret plain text are -\n\nv.   {secret_plaintext.decode('UTF-8')}\n")
    else:
        print("Unable to find the key of 20 bit.") 

if __name__ == "__main__":
    main()
