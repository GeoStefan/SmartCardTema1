from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA

class EncryptedMessage:
    def __init__(self, cipertext, tag, nonce):
        self.cipertext = cipertext
        self.tag = tag
        self.nonce = nonce


class Aes:

    def encrypt(self, message, key):
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        cipertext, tag = cipher.encrypt_and_digest(message)
        return (cipertext, nonce, tag)

    def decrypt(self, encryptedMessage, key):
        cipher = AES.new(key, AES.MODE_EAX, nonce=encryptedMessage['nonce'])
        plaintext = cipher.decrypt(encryptedMessage['cipertext'])
        try:
            cipher.verify(encryptedMessage['tag'])
            print("DECRYPT WITH AES: Message is authentic")
        except ValueError:
            print("DECRYPT WITH AES: Corrupted message")
        return plaintext


class Rsa:
    def generateKey(self):
        self.key = RSA.generate(2048)
        print(self.key)

    def exportKey(self, filename):
        f = open(filename, 'wb')
        f.write(self.key.export_key('PEM'))
        f.close()

    def importKey(self, filename):
        f = open(filename, 'r')
        key = RSA.import_key(f.read())
        f.close()
        return key

    def importKey2(self, message):
        return RSA.importKey(message)

    def savePublicKey(self, filename):
        f = open(filename, 'wb')
        f.write(self.key.publickey().export_key())
        f.close()

    def loadPublicKey(self, filename):
        f = open(filename,'rb')
        key = RSA.import_key(f.read())
        f.close()
        return key

    def encrypt(self, message, key):
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(message)

    def decrypt(self, message, key):
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(message)


class Sign:
    def sign(self, message, keyFilemane):
        key = RSA.import_key(open(keyFilemane).read())
        h = SHA256.new(message)
        return pkcs1_15.new(key).sign(h)

    def verifySignature(self, message, signature, keyFilename):
        key = Rsa().loadPublicKey(keyFilename)

        h = SHA256.new(message)
        try:
            pkcs1_15.new(key).verify(h, signature)
            print("Valid signature")
            return True
        except (ValueError, TypeError):
            print("Invlaid signature")
            return False

if __name__ == "__main__":
    serverKey = 'server-key.pem'
    clientKey = 'client-key.pem'
    pgKey = 'pg-key.pem'
    publicKeyServer = 'server-public.der'
    publicKeyClient = 'client-public.der'
    publicKeyPG = 'pg-public.der'
    # generate RSA key for client
    rsaClient = Rsa()
    rsaClient.generateKey()
    rsaClient.exportKey(clientKey)
    rsaClient.savePublicKey(publicKeyClient)
    # generate RSA key for merchant
    rsaServer = Rsa()
    rsaServer.generateKey()
    rsaServer.exportKey(serverKey)
    rsaServer.savePublicKey(publicKeyServer)
    # generate RSA key for PG
    rsaPG = Rsa()
    rsaPG.generateKey()
    rsaPG.exportKey(pgKey)
    rsaPG.savePublicKey(publicKeyPG)