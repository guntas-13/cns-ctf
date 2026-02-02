from hashlib import sha256, sha1, md5

n = 101329648295894964818358303618974533420693033108821596850450462143243174048538085644619975437953253035757784044168162490750582079674316643795759412402735698592847349082737242255102383633798849856657770730704540381704901463937799606467271534209224173203580250140928813252478260325642675804488444252504491108639
e = 65537
secret_message = b"Hello Bob! This is a secret message, to be kept within CNS431."

# h = int.from_bytes(sha256(secret_message).digest(), 'big')
# h = int.from_bytes(sha1(secret_message).digest(), 'big')
# h = int.from_bytes(md5(secret_message).digest(), 'big')

# h = int.from_bytes(sha256(secret_message).hexdigest().encode(), 'big')
# h = int.from_bytes(sha1(secret_message).hexdigest().encode(), 'big')
# h = int.from_bytes(md5(secret_message).hexdigest().encode(), 'big')

# int.from_bytes(str(h_int).encode(), 'big')
# h = int.from_bytes(str(int.from_bytes(sha256(secret_message).digest(), 'big')).encode(), 'big')
# h = int.from_bytes(str(int.from_bytes(sha1(secret_message).digest(), 'big')).encode(), 'big')
h = int.from_bytes(str(int.from_bytes(md5(secret_message).digest(), 'big')).encode(), 'big')

print(f"Hash of secret message: {h}")

# s = h^d mod n (where d is Alice's private key)
# but she mixed up and used e instead of d
# so s = h^e mod n
print(f"s: {pow(h, e, n)}")
