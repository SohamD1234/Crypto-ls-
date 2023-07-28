from operator import itemgetter

lowercase=str.lower('abcdefghijklmnopqrstuvwxyz')

def vignere_key(input):
    """
    Performs a cryptanalysis on the given input to find out the key length and the key
    Parameters:
        input_text (str): The ciphertext to be decrypted.

    Returns:
        key: The key for the Vignere_Decryption
    """
    nchars = 26
    ordA = ord('a')
    target_freqs = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,0.06094, 0.06966, 0.00153, 0.00772, 0.04025,0.02406, 0.06749,0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
    sorted_targets = sorted(target_freqs)

    def frequency(input):
    	#Helper function to create a freq table (in a 2D array)
        result = [[c, 0.0] for c in lowercase]
        for c in input:
            result[c - ordA][1] += 1
        return result

    def correlation(input):
    	#Helper function to find the corr value with the target_freqs
        result = 0.0
        freq = frequency(input)
        freq.sort(key=itemgetter(1))

        for i, f in enumerate(freq):
            result += f[1] * sorted_targets[i]
        return result

    cleaned = [ord(c) for c in input.lower() if c.islower()]
    best_len = 0
    best_corr = -100.0
	
    for i in range(2, len(cleaned) // 20):
        fragments = [[] for _ in range(i)]
        for j, c in enumerate(cleaned):
            fragments[j % i].append(c)

        corr = -0.5 * i + sum(correlation(fragment) for fragment in fragments)

        if corr > best_corr:
            best_len = i
            best_corr = corr

    if best_len == 0:
        return 0

    fragments = [[] for _ in range(best_len)]
    for i, c in enumerate(cleaned):
        fragments[i % best_len].append(c)

    freqs = [frequency(fragment) for fragment in fragments]

    key = ""
    for fr in freqs:
        fr.sort(key=itemgetter(1), reverse=True)

        m = 0
        max_corr = 0.0
        for j in range(nchars):
            corr = 0.0
            c = ordA + j
            for frc in fr:
                d = (ord(frc[0]) - c) % nchars
                corr += frc[1] * target_freqs[d]

            if corr > max_corr:
                m = j
                max_corr = corr

        key += chr(m + ordA)

    return key

def vignere_decrypt(input_text, key):
    """
    Decrypts a Vigenere cipher given the input text and the key.

    Parameters:
        input_text (str): The ciphertext to be decrypted.
        key (str): The key used for encryption.

    Returns:
        str: The decrypted plaintext.
    """

    def shift(char, shift_amount):
        # Helper function to perform the shift operation on a character
        if char.isupper():
            return chr((ord(char) - ord('A') - shift_amount) % 26 + ord('A'))
        elif char.islower():
            return chr((ord(char) - ord('a') - shift_amount) % 26 + ord('a'))
        else:
            return char

    decrypted_text = ""
    key_len = len(key)
    key_shifts = [ord(k.upper()) - ord('A') for k in key]
    count = 0
    # Decrypt each character in the input text
    for i, char in enumerate(input_text):
    	shift_amount = key_shifts[count % key_len]
    	if char.isalpha(): 
    	    count += 1
    	decrypted_text += shift(char, shift_amount)

    return decrypted_text


def main():
    encoded = input("Enter the encrypted message:\n")
    key = vignere_key(encoded.lower())
    if key != 0:
	    decoded = vignere_decrypt(encoded.lower(),key)
	    print ("\nKey:\n",key)
	    print ("\nText:\n",decoded)
    else:
        print ("The given text is too short to be decoded!")
        
if __name__ == "__main__":
	main()
