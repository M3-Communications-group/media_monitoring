from pymongo import MongoClient
import bcrypt

client = MongoClient('mongodb://localhost:27017/')
db = client['media_monitoring']

admin_username = 'user1'
admin_password = 'password1'
admin_email = 'email1'

hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

admin_user = {
    "username": admin_username,
    "password": hashed_password,
    "email": admin_email
}

if db.admins.find_one({"username": admin_username}):
    print("Admin user already exists.")
else:
    db.admins.insert_one(admin_user)
    print("Admin user inserted successfully.")
