def bytes_xor_repeat(x, y):
    return bytes([x[i] ^ y[i % 3] for i in range(len(x))])

print(bytes_xor_repeat(bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "utf-8"), b"ICE").hex())
