import numpy as np
import Transformations


def load_state(plaintext):
    state = np.array_split(plaintext, 4)
    state = np.concatenate(([state[0]], [state[1]], [state[2]], [state[3]]))
    return state


def load_output(state):
    output = np.array_split(state, 4)
    output = np.concatenate((output[0], output[1], output[2], output[3])).tobytes('C')
    return output


def cypher(plaintext, key):
    match len(key)*8:
        case 128:
            rounds = 10
        case 192:
            rounds = 12
        case 256:
            rounds = 14

    w = Transformations.key_expansion(key, rounds, 4)
    state = load_state(bytearray(plaintext)).T

    print("round: 0")
    print(state)

    print("add_round_key:")
    print(w[0:4].T)
    state = Transformations.add_round_key(state, w[0:4].T)
    print("\n")
    for i in range(1, rounds):
        print("round: " + str(i))
        print(state)
        state = Transformations.sub_bytes(state)
        print(state)
        state = Transformations.shift_row(state)
        print(state)
        state = Transformations.mix_columns(state)
        print(state)
        print("add_round_key:")
        print(w[i * 4:(i + 1) * 4].T)
        state = Transformations.add_round_key(state, w[i * 4:(i + 1) * 4].T)
        print(state)
        print("\n")

    print("round: " + str(i + 1))
    print(state)
    state = Transformations.sub_bytes(state)
    print(state)
    state = Transformations.shift_row(state)
    print(state)
    print("add_round_key:")
    print(w[(i + 1) * 4:(i + 2) * 4].T)
    state = Transformations.add_round_key(state, w[(i + 1) * 4:(i + 2) * 4].T)
    print(state)

    return load_output(state.T)


def inv_cypher(ciphertext, key):
    match len(key)*8:
        case 128:
            rounds = 10
        case 192:
            rounds = 12
        case 256:
            rounds = 14

    print("round: " + str(rounds))
    w = Transformations.key_expansion(key, rounds, 4)
    state = load_state(bytearray(ciphertext)).T
    print(w[rounds * 4:(rounds + 1) * 4].T)
    state = Transformations.add_round_key(state, w[rounds * 4:(rounds + 1) * 4].T)
    print(state)
    print("\n")

    for i in range(rounds-1, 0, -1):
        print("round: " + str(i))
        print(state)
        state = Transformations.inv_shift_rows(state)
        print(state)
        state = Transformations.inv_sub_bytes(state)
        print(state)
        print("add_round_key:")
        print(w[i * 4:(i + 1) * 4].T)
        state = Transformations.add_round_key(state, w[i * 4:(i + 1) * 4].T)
        print(state)
        state = Transformations.inv_mix_columns(state)
        print(state)
        print("\n")

    print("round: " + str(i + 1))
    print(state)
    state = Transformations.inv_shift_rows(state)
    print(state)
    state = Transformations.inv_sub_bytes(state)
    print(state)
    print("add_round_key:")
    print(w[(i - 1) * 4: i * 4].T)
    state = Transformations.add_round_key(state, w[0: 4].T)
    print(state)

    return load_output(state.T)


# Encrypts string to array of bytes using AES
def encrypt(plain_text):
    arrayified_message = Transformations.arrayify(plain_text)
    cypher_text = np.array([])
    for word in arrayified_message:
        cypher_text = np.append(cypher(word, Transformations.read_key()), cypher_text)
    print(cypher_text)
    return cypher_text


# Decrypts array of bytes to string using AES
def decrypt(cypher_text):
    plain_text = ''
    for word in reversed(cypher_text):
        decoded = inv_cypher(word, Transformations.read_key()).decode('utf-8')
        plain_text += decoded
    print(plain_text)
    return plain_text
