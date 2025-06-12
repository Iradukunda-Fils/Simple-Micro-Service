# from functools import wraps

# # A basic logging decorator to demonstrate
# def log_decorator(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         print("✅ Decorator triggered")
#         return func(*args, **kwargs)
#     return wrapper

# def method_decorator(decorator, name=''):
#     def decorator_wrapper(obj):
#         if name:
#             # Decorate method by name
#             method = getattr(obj, name)
#             decorated_method = decorator(method)
#             setattr(obj, name, decorated_method)
#             return obj
#         else:
#             # When used as a decorator, handle different method types
#             def _inner(method_or_descriptor):
#                 # If it's a classmethod or staticmethod, we need to handle it specially
#                 if isinstance(method_or_descriptor, classmethod):
#                     # Extract the actual function, decorate it, then wrap back in classmethod
#                     actual_func = method_or_descriptor.__func__
#                     decorated_func = decorator(actual_func)
#                     return classmethod(decorated_func)
#                 elif isinstance(method_or_descriptor, staticmethod):
#                     # Extract the actual function, decorate it, then wrap back in staticmethod
#                     actual_func = method_or_descriptor.__func__
#                     decorated_func = decorator(actual_func)
#                     return staticmethod(decorated_func)
#                 else:
#                     # Regular method
#                     return decorator(method_or_descriptor)
#             return _inner
#     return decorator_wrapper

# print("\n" + "=" * 50)
# print("SOLUTION 2: Using enhanced method_decorator")
# print("=" * 50)

# # 👇 DO NOT DECORATE THE WHOLE CLASS
# class Goo:
#     dataset = "big"
#     @classmethod
#     @method_decorator(log_decorator)
#     def data(cls):
#         print("👋 Inside Goo.data()")
#         return "datas"

# # ✅ Now call the method properly
# print(Goo.data())

# class A:
#     def __init__(self):
#         self.a = "A's attribute"

#     def method_a(self):
#         return "Method from A"

# class B:
#     def __init__(self):
#         self.b = "B's attribute"

#     def method_b(self):
#         return "Method from B"
# class C:
#     def __init__(self):
#         self.c = "C's attribute"

#     def method_c(self):
#         return "Method from C"

# Goo = type("Goo", (A,B,C), {"data":"data", "hood": "hello, World"})  # class name, base classes, attributes

# print(Goo.__dict__)  # Should show the class attributes and methods


# def data(self): ...

# type Data = B

# print(isinstance(data, type))  # Should show <class '__main__.B'>
# print(A)


# MyClass = type('MyClass', (), {'greet': lambda self: "Hello!"})
# MyClass.__doc__ = "This is a dynamically created class"
# obj = MyClass()
# print(obj.greet())  # "Hello!"

# print(MyClass.__doc__)  # "This is a dynamically created class"
