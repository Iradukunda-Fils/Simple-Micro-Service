
class D:
    ...

class SettingsReference(str):
    """
    String subclass which references a current settings value. It's treated as
    the value in memory but serializes to a settings.NAME attribute reference.
    """

    def __new__(self, value, setting_name):
        return str.__new__(self, value)

    def __init__(self, value, setting_name):
    
        self.cache = {
            setting_name: value
        }
    
        setattr(self, setting_name, value)
        
    def display(self):
        """
        Returns the string representation of the settings reference.
        This method is used to display the value of the settings reference.
        """
        return str("Properties are: ") + ", ".join(f"{k} = {v}" for k, v in self.cache.items())
        
    @classmethod
    def as_view(cls, value, setting_name):
        """
        Returns a new instance of SettingsReference with the given value and setting name.
        This method is used to create a view of the settings reference.
        """
        return cls(value, setting_name)
    
    

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
    
    # data = SettingsReference.as_view("KEY", "AUTH_KEY")
    # print("SettingsReference instance:", data.display())
    # data = data.__class__.__name__
    # print("Class name of %(other)s: %(data)s" % {"data": data, "other": "hello, World"} or {"data": "D"})
    # data = dir("rirectory" + data)
    # data = data.setdefault("DJANG", "authsettings")
    # print("Directory of 'rirectory':", data)
    text = "hello"
    encoded_text = text.encode()
    print(encoded_text)
    
    


if __name__ == "__main__":
    main()
