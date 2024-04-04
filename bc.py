import bcrypt

password = b"super secret password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)
