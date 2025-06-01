import secrets

def main():
    # print("print random integer bellow 10", secrets.randbelow(10))
    print(secrets.choice(("data", "copy", "fire", "buffer", "father")))  # Might print '5'
    print(secrets.token_hex(16))  # 32 hex characters
    print(secrets.token_urlsafe(16)) 
    print(secrets.token_bytes(16))  # 16 random bytes
    print(secrets.randbits(16))  # 16 random bits
    print(secrets.randbits(16).to_bytes(2, 'big'))  # Convert to bytes
    print(secrets.randbits(16).to_bytes(2, 'big').hex())  # Convert to hex string
    print(secrets.randbits(16).to_bytes(2, 'big').hex().upper())  # Convert to uppercase hex string
    print(secrets.randbits(16).to_bytes(2, 'big').hex().upper().encode('utf-8'))  # Convert to bytes
    print(secrets.randbits(16).to_bytes(2, 'big').hex().upper().encode('utf-8').decode('utf-8'))  # Convert to string
    print(isinstance(int(''.join(secrets.choice('0123456789') for _ in range(8))), int))  # Check if it's an integer
    


    
    
    
if __name__ == "__main__":
    main()