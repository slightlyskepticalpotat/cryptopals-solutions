# PyCryptodome unpadding is faster

def unpad(text, block_size):
    padding, removed = text[-1], 0
    while 0 <= text[-1] <= (block_size - 1) and text[-1] == padding:
        text, removed = text[:-1], removed + 1
    if padding == removed or padding > (block_size - 1):
        return text
    raise Exception("Padding Error")
    
print(unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16))
try:
    print(unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16))
except Exception as e:
    print(str(e))
try:
    print(unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16))
except Exception as e:
    print(str(e))
