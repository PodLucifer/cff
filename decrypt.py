import marshal
import sys

def decrypt_file(input_filename):
    try:
        # Read the encrypted content from the file
        with open(input_filename, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt using marshal.loads (unmarshal the data)
        decrypted_data = marshal.loads(encrypted_data)

        # Generate the output filename
        output_filename = f"{input_filename.split('.')[0]}-dec.txt"

        # Save the decrypted content to the new file
        with open(output_filename, 'w') as f:
            f.write(decrypted_data)

        print(f"Decrypted content has been saved to {output_filename}")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <filename>")
    else:
        input_filename = sys.argv[1]
        decrypt_file(input_filename)
