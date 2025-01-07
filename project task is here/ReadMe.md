# This project is based on AES

## Part 1 of the Assignment

### Code Explanation -
This programing assignment perform the AES encryption and the decryption in CBC mode by using a custom 16 bytes of a key and then expansion from a shorter size 20-bit key. It also implementing the brute force approach for finding the correct key and for decrypting the ciphertext also.

#### Key Functions -
1. Key Expansion -
   - Converting the 20 bit key size into the 16 byte key for the AES-128 encryption.
   - It includes all the intermediate bytes for calculating and using modular arithmetic.

2. File Loading -
   - Loading the plaintext and the ciphertext from the specified file path.

3. Encryption & Decryption process -
   - AES encryption and the decryption process using a CBC mode with an IV initialized with the initially zero vector.

4. Brute Force -
   - this approach iterate through all the possible 20 bit keys so that ot can find the correct one.

5. Driver Function -
   - It loads the plaintext and the ciphertext, to perform the brute force approach, and to reveals the secret plaintext.

### Output -
This program will displays as a output the founded key and its expanded version also. It is also decrypts a hidden secret plaintext.

How ouput is look's -

Part - 1

1st part, 
Key is founded - 8e6330
This is the key after expansan - 8e94635ae87bde371e30e71d3b6b516e
Given plane text are -

i.   Counterclockwise
ii.  sonicthehedgehog
iii. TheDeterminantor
iv.  FeedbackRegister

And the secret plain text are -

v.   mediumaquamarine

---

## Part 2 of the Assignment

### Code Explanation -
This part of assignment will implements the **Meet in the Middle Attack** on AES encryption.

#### Key Functions:
1. Key Expansion -
   - Importing the external function so that it expand the keys into a 16 byte AES key.

2. Encryption Dictionary -
   - Generating all the possible intermediate encrypted values for the first plaintext by using all the 16 bit keys.

3. Brute Force Approach on Second Key -
   - This approach will iterates through all the possible 16 bit keys so that it can find the matches with the intermediate values.

4. Verification and Decryption -
   - Here it verifies the founded key and the decrypted hidden plaintext.

5. Meet in the Middle Attack -
   - It combines the above function into the successfully revealed secret plaintext.

### Output -
This program will reveals the matched keys and the decrypted hidden plaintext also.

How ouput is look's -

Part - 2

i found the key's found-

Key 1 - b2df & Key 2 - 16c3

Given plane text are -

i.     Hydrodynamometer
ii.    Circumnavigation
iii.   Crystallographer
iv.    Microphotography

And the secret Plaintext is here - 

v.     paddlingcanoeist

---

### Additional Notes -
1. Please makes sure you have a required plaintext and the ciphertext files in the specified paths or in the same path.
2. Install all the necessary libraries, especially cryptography, before running this code.

