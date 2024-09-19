import struct
import protocol
def encode_key_in_magic_number(key):
    # Assume key is a string of 4 characters
    magic_number = protocol.ENCRYPTION_KEY
    key_bytes = key.encode('utf-8')
    
    # Pack the magic number and key into a byte string
    packed = struct.pack('>II', magic_number, int.from_bytes(key_bytes, 'big'))
    
    return packed

def decode_key_from_magic_number(packed):
    # Unpack the byte string
    magic, key_int = struct.unpack('>II', packed)
    
    # Check if the magic number is correct
    if magic != protocol.ENCRYPTION_KEY:
        raise ValueError("Invalid magic number")
    
    # Convert the key back to a string
    key = key_int.to_bytes(4, 'big').decode('utf-8')
    
    return key

# Example usage
original_key = "KEY!"
encoded = encode_key_in_magic_number(original_key)
decoded_key = decode_key_from_magic_number(encoded)

print(f"Original key: {original_key}")
print(f"Encoded: {encoded.hex()}")
print(f"Decoded key: {decoded_key}")