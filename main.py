import math


def toBinary(a):  # type(a) = String. Returns a list of given string's each byte in Binary form.
    l, m = [], []
    for i in a:
        l.append(ord(i))
    for i in l:
        m.append(int(bin(i)[2:]))
    return m


def toString(a):  # type(a) = List<String>. Returns a String value of given list of binary values.
    l = []
    m = ""
    for i in a:
        b = 0
        c = 0
        k = int(math.log10(i)) + 1
        for j in range(k):
            b = ((i % 10) * (2 ** j))
            i = i // 10
            c = c + b
        l.append(c)
    for x in l:
        m = m + chr(x)
    return m


def is_prime(num):  # Check if the "num" is prime or not.
    for n in range(2, int(num ** 0.5) + 1):
        if num % n == 0:
            return False
    return True


def prime_factors(number):  # Returns list of prime_factors of a given "number"
    factors = []
    for i in range(2, number + 1):
        if number % i == 0:
            count = 1
            for j in range(2, (i // 2 + 1)):
                if i % j == 0:
                    count = 0
                    break
            if count == 1:
                factors.append(i)
    return factors


def selecting_generator(g, p):  # Deciding if the user's g input is valid or not.
    prime_factors_p = prime_factors(p - 1)
    for i in range(len(prime_factors_p)):
        power = (p - 1) / prime_factors_p[i]
        value = (g ** power) % p
        if value == 1:
            return False
    return True


def Alice_public_key_generation(a, g, p):  # Public key generation of Alice w.r.t Diffie-Hellman
    return (g ** a) % p


def Bob_public_key_generation(b, g, p):  # Public key generation of Bob w.r.t Diffie-Hellman
    return (g ** b) % p


def input_test(a, b, g, p):  # Checking requirements of the Diffie-Hellman
    if p > a and p > b and p > g:
        return True
    else:
        return False


def creating_common_secret_key(a, g, p, b):  # Generation common key for the both receiver and sender side and
    # checking they are equal or not. If equal, shared common key equals one
    # of them. Else return False
    alice_common_key = (Bob_public_key_generation(b, g, p) ** a) % p
    bob_common_key = (Alice_public_key_generation(a, g, p) ** b) % p
    if alice_common_key == bob_common_key:
        common_secret_key = alice_common_key
        return common_secret_key
    else:
        return False


def get_binary(number, offset=0):  # type(number) = int. Returns binary form of a given "number".
    binary_number = format(number, 'b').zfill(offset)
    return int(binary_number)


def binaryToDecimal(binary):  # type(binary) = int. Return decimal form of a binary number.

    decimal, i, n = 0, 0, 0
    while (binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        i += 1
    return decimal


def encrypt_cbc_round(ci, common_key, pi):  # All parameters should be given in integer form.  This
    # function represents each round of the CBC encryption method.
    first_xor = ci ^ pi  # Making XOR operation between ci and pi. ci equals IV for the first round and equals the
    # ciphertext[i-1] (or each_round) for the rest of the rounds. i = round number.
    Ci = common_key ^ first_xor  # Making Ek process which is making XOR operation between the output of the first
    # XOR operation and created and shared common key.
    return Ci


def decrypt_cbc_round(ci, common_key, pi):  # All parameters should be given in integer form. This function
    # represents each round of the CBC decryption method.
    ek = pi ^ common_key  # Making XOR operation between pi and common key.
    Ci = ek ^ ci  # Making  XOR operation between ek and ci. ci equals IV for the first round and equals the
    # ciphertext[i-1] for the rest of the rounds. i = round number.
    return Ci


def encryption(a, g, p, b, iv, message):  # This function represents whole encryption process of the given CBC
    # Encryption Mode.
    each_round = 0
    encrypt_message = []
    common_key = creating_common_secret_key(a, g, p, b)
    message_in_binary = toBinary(message)
    for i in range(len(message_in_binary)):
        if i == 0:
            each_round = encrypt_cbc_round(iv, common_key, binaryToDecimal(message_in_binary[i]))
            encrypt_message.append(get_binary(each_round))
        else:
            each_round = encrypt_cbc_round(each_round, common_key, binaryToDecimal(message_in_binary[i]))
            encrypt_message.append(get_binary(each_round))
    return encrypt_message


def decryption(a, g, p, b, iv, ciphertext_array):  # This function represents whole encryption process of the given CBC
    # Encryption Mode's Decryption process. ciphertext_array should be in binary form.
    decrypt_message = []
    common_key = creating_common_secret_key(a, g, p, b)
    for i in range(len(ciphertext_array)):
        if i == 0:
            each_round = decrypt_cbc_round(iv, common_key, binaryToDecimal(int(ciphertext_array[i])))
            decrypt_message.append(get_binary(each_round))
        else:
            each_round = decrypt_cbc_round(binaryToDecimal(int(ciphertext_array[i - 1])), common_key,
                                           binaryToDecimal(int(ciphertext_array[i])))
            decrypt_message.append(get_binary(each_round))
    return decrypt_message


def main():
    while True:
        # Taking inputs (a, b, p, g, IV, message) from the user.
        try:
            a = int(input("Private number for Alice (a): "))
            b = int(input("Private number for Bob (b): "))
            p = int(input("Enter a prime number (p): "))
            g = int(input("Enter a generator (g): "))
            iv = int(input("Enter a initial vector (IV): "))
            message = input("Enter message: ")

            # Checking inputs for validation.
            if not input_test(a, b, g, p):
                print("Check your a, b, g, p values!")
            elif not is_prime(p):
                print("p is not a prime number!")
            elif not selecting_generator(g, p):
                print("Generator (g) is not valid!")
            else:
                break
        except ValueError:
            print("Please enter integer numbers for a, b, p, g, iv")

    # Encryption and Decryption done in here.
    encrypted_message = encryption(a, g, p, b, iv, message)
    decrypted_message = decryption(a, g, p, b, iv, encrypted_message)

    # To give a little understanding to the user what is going on through the whole encryption and decryption process.
    print("Public key of Alice: ", Alice_public_key_generation(a, g, p))
    print("Public key of Bob: ", Bob_public_key_generation(b, g, p))
    print("Used Shared Common Key: ", creating_common_secret_key(a, g, p, b))
    print("Given Plaintext: ", message)
    print("Plaintext in Binary = ", toBinary(message))
    print("Ciphertext: ", encrypted_message)
    print("Ciphertext in String: ", toString(encrypted_message))
    print("Decryption of Ciphertext in Binary: ", decrypted_message)
    print("Decryption of Ciphertext in String: ", toString(decrypted_message))


main()
