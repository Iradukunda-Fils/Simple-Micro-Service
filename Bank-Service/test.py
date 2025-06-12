
from functools import wraps

def log_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Decorator triggered ✅")
        return func(*args, **kwargs)
    return wrapper

def method_decorator(decorator, name=None):
    
    def decorator_wrapper(instance_or_method):
        nonlocal name
        if name is None or (isinstance(instance_or_method, type) and name is not None and hasattr(instance_or_method, name)):
            # If it's a class, we need to apply the decorator to its methods
            print(f"Applying decorator {decorator.__name__} on class methods ✅")
            for name, method in instance_or_method.__dict__.items():
                if callable(method):
                    decorated_method = decorator(method)
                    setattr(instance_or_method, name, decorated_method)
            return instance_or_method
        elif callable(instance_or_method):
            print(f"Applying decorator {decorator.__name__} on method ✅")
            # If it's a method, apply the decorator directly
            return decorator(instance_or_method)
        else:
            raise TypeError(f"Expected a callable or class, got {type(instance_or_method).__name__}")
    return decorator_wrapper


@method_decorator(log_decorator, name="data")
class Goo:
    @classmethod
    @log_decorator
    def data(cls):
        print("Inside method 👋")
        return "datas"

# @log_decorator
# def good():
#     print("Good function called"+" ✅")

    
    
def main():
    # print("print random integer bellow 10", secrets.randbelow(10))
    # print(secrets.choice(("data", "copy", "fire", "buffer", "father")))  # Might print '5'
    # print(secrets.token_hex(16))  # 32 hex characters
    # print(secrets.token_urlsafe(16)) 
    # print(secrets.token_bytes(16))  # 16 random bytes
    # print(secrets.randbits(16))  # 16 random bits
    # print(secrets.randbits(16).to_bytes(2, 'big'))  # Convert to bytes
    # print(secrets.randbits(16).to_bytes(2, 'big').hex())  # Convert to hex string
    # print(secrets.randbits(16).to_bytes(2, 'big').hex().upper())  # Convert to uppercase hex string
    # print(secrets.randbits(16).to_bytes(2, 'big').hex().upper().encode('utf-8'))  # Convert to bytes
    # print(secrets.randbits(16).to_bytes(2, 'big').hex().upper().encode('utf-8').decode('utf-8'))  # Convert to string
    # print(isinstance(int(''.join(secrets.choice('0123456789') for _ in range(8))), int))  # Check if it's an integer
    
    
    print(Goo.data())
    
    # good()
    
    # if hasattr(list, '__iter__'):
    #     print("main is callable")
    # if not callable(goo):
    #     print("main is callable")
        
    # Check if main is callable
    # if hasattr(main, '__call__'):
    #     print("main has __call__ method")
    # else:
    #     print("main does not have __call__ method")
    #     raise ValueError(
    #             "The object '%s' is not callable." % method
    #         )
    #     raise TypeError(
    #             "The object '%s' is not callable." % method
            # )
    


    
    
    
if __name__ == "__main__":
    main()