import marshal

# Example data to serialize
data = "This is a test string for marshal serialization."

# Open the file in binary write mode to store the serialized data
with open('test_marshal.txt', 'wb') as f:
    # Use marshal.dump to serialize the data and write it to the file
    marshal.dump(data, f)

print("Test file 'test_marshal.txt' has been created.")
