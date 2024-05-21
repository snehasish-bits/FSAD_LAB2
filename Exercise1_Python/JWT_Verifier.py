import jwt

def verifyJWT(jwt_token, jwt_secret):
    try:
        decoded = jwt.decode(jwt_token, jwt_secret, algorithms=['HS384'])
        print(decoded)
    except jwt.exceptions.JWTError as e:
        print("Invalid JWT:", e)
