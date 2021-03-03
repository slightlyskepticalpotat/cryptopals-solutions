def bytes_xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

hex1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
hex2 = bytes.fromhex("686974207468652062756c6c277320657965")
print(bytes_xor(hex1, hex2).hex())
