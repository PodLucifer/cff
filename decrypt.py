import marshal
import sys
import types

def decrypt_file(file_path):
    with open(file_path, "rb") as f:
        compiled_code = marshal.load(f)  # Load the marshaled code
    
    if isinstance(compiled_code, types.CodeType):
        exec(compiled_code)  # Execute the decrypted Python code
    else:
        print("Invalid marshaled code file.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <file.py>")
    else:
        decrypt_file(sys.argv[1])
