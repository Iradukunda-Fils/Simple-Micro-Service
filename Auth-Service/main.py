
class D:
    ...

def main():
    # print("Hello from auth-service!", end="\n\n")
    
    # data = "Bearero *(#Jonno(()(#J)(_)&@*^#@%&#^@*@#%@$!%$@!^&#!%@!%%&#@^#@%#$^!@%6!@&DH&YF^FVXVYYV@S^D@F^S#))Bearer"
    # data = data.strip()
    # print("Validating token:", data)
    
    # if data.startswith("Bearer "):
    #     data = len(data[7:])
    #     print(f"Token validated start with Bearer, length: {data} characters")
    # elif data.endswith("Bearer"):
    #     data = len(data[:-6])
    #     print("Token validated end with Bearer, length:", data, "characters")
    # else:
    #     data = len(data)
    #     print("Token not validated, length:", data, "characters")
    
    data = D()
    # data = data.__class__.__name__
    print("Class name of D:", data)
    data = data.setdefault("DJANG", "authsettings")
    


if __name__ == "__main__":
    main()
