# d06b91365ae9f3e59308b84ba71b6e53 123b8dcac31578ea1c4ee5496fbbce0e
# d06b91365ae9f3e59308b84ba71b6e53 688109854f7dc49373de770bc6390dcc

iv = bytes.fromhex("d06b91365ae9f3e59308b84ba71b6e53")

# index of '?' in "user:c?s" and "pass:c?f"
IDX = 6

# Flip '?' → 'n'
iv_user = bytearray(iv)
iv_user[IDX] ^= 0x51

# Flip '?' → 't'
iv_pass = bytearray(iv)
iv_pass[IDX] ^= 0x4b

c_user = bytes.fromhex("123b8dcac31578ea1c4ee5496fbbce0e")
c_pass = bytes.fromhex("688109854f7dc49373de770bc6390dcc")

username_hex = (bytes(iv_user) + c_user).hex()
password_hex = (bytes(iv_pass) + c_pass).hex()

print("username_hex =", username_hex)
print("password_hex =", password_hex)
