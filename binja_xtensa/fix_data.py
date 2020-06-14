import binascii
import csv


with open("fixed.csv", "w") as wfile:
    with open("test_mnemonics.csv", "r") as file:
        reader = csv.reader(file)
        for row in reader:
            opcode, mnem = row
            # Need to byte-swap opcode
            data = binascii.unhexlify(opcode)
            reverse_data = bytearray(data)
            reverse_data.reverse()
            wfile.write(f"{binascii.hexlify(reverse_data).decode('utf-8')},{mnem}\n")
