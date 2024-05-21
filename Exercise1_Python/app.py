from JWT_Generator import generateJWT
from JWT_Verifier import verifyJWT

secret = "Snehasish_Pati@2023sl93010" #Secret for generating JWT Tokens

print("Generated JWT: ")

jwtToken = generateJWT(secret)

print("Decoded JWT:")

verifyJWT(jwtToken, secret)