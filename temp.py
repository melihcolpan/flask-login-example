from passlib.handlers.md5_crypt import md5_crypt

# hash = md5_crypt.encrypt("123")
#
# print hash

print md5_crypt.verify("123", '$1$2aYefWVj$BicgKcTZTh6kN1T64LZXT/')
