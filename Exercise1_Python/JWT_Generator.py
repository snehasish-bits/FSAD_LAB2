import jwt
import time

payload = {
    "username": "Tikul",
    "userID": 5672,
    "exp": int(time.time()) + 60 * 60 * 2  #Setting expiration time as 2 hours
}

def generateJWT(secret):
    #Generating JWT
    token = jwt.encode(payload, secret, algorithm='HS384')

    print(token)

    return token