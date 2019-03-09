import socket
import crypto
import pickle
import datetime

rsaKeyFilename = 'client-key.pem'
publicKeyServer = 'server-public.der'
publicKeyPG = 'pg-public.der'

if __name__ == "__main__":
    HOST = 'localhost'
    PORT = 8999
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print('M-am conectat')

        # Alegerea produsului
        data = s.recv(1024)
        produse = pickle.loads(data)
        print(produse)
        produs = input('Alege produsul: ')

        key = crypto.Rsa().importKey(rsaKeyFilename)
        pubKM = crypto.Rsa().loadPublicKey(publicKeyServer)
        pubKPG = crypto.Rsa().loadPublicKey(publicKeyPG)
        AESkey = b'1234567890123456'
        AESkeyPG = b'0123456789123456'

        # setup sub-protocol
        # step 1
        print('Step 1')
        encryptedMessage = crypto.Aes().encrypt(key.publickey().export_key(), AESkey)
        encryptedKey = crypto.Rsa().encrypt(AESkey, pubKM)
        s.sendall(pickle.dumps({'cipertext': encryptedMessage[0],
                                'nonce': encryptedMessage[1],
                                'tag': encryptedMessage[2],
                                'key': encryptedKey}))
        print('Am trimis RSA pubKC = ', key.publickey().export_key(), '   client AESkey = ', AESkey, '\n')

        # step 2
        print('Step 2')
        data = pickle.loads(s.recv(10000))
        data = {'cipertext': data['cipertext'][0], 'nonce': data['cipertext'][1], 'tag': data['cipertext'][2]}
        message = crypto.Aes().decrypt(data, AESkey)
        content = pickle.loads(message)
        SID = content['sid']
        print('Am primit SID = ', SID)
        print('Verific semnatura merchant...')
        if crypto.Sign().verifySignature(content['sid'], content['signedSid'], publicKeyServer):
            print("Correct signature\n")
        else:
            print("Invalid signature, Closing the connection...")
            s.close()

        # exchange sub-protocol
        # step 3
        print('Step 3')
        pi = {'cardN': b'0000111122223333',
              'cardExp': datetime.datetime(2020, 9, 10),
              'cCode': b'codSecret',
              'amount': produse[produs],
              'sid': SID,
              'pubKC': key.publickey().export_key(),
              'nc': 1,
              'M': b'ceva'}
        piBytes = pickle.dumps(pi)
        pm = {'pi': piBytes,
              'signedPi': crypto.Sign().sign(piBytes, rsaKeyFilename)}
        encryptedPm = crypto.Aes().encrypt(pickle.dumps(pm), AESkeyPG)
        encryptedPGkey = crypto.Rsa().encrypt(AESkeyPG, pubKPG)
        print('Am criptat PM cu PG AESkey = ', AESkeyPG,'     PG RSA PubKPG = ', pubKPG.exportKey())
        poContent = pickle.dumps({
            'orderDesc': produs,
            'sid': SID,
            'amount': produse[produs]
        })
        po = {
            'poContent': poContent,
            'signedPo': crypto.Sign().sign(poContent, rsaKeyFilename)
        }

        encryptedMessage = crypto.Aes().encrypt(pickle.dumps({'encryptedPm': encryptedPm,
                                                              'encryptedPGkey': encryptedPGkey,
                                                              'po': po}), AESkey)
        encryptedKey = crypto.Rsa().encrypt(AESkey, pubKM)
        print('Am criptat intregul mesaj cu MERCHANT AESkey = ', AESkey, '     MERCHANT RSA PubKM = ', pubKM.exportKey())
        s.sendall(pickle.dumps({'encryptedMessage': encryptedMessage, 'encryptedKey': encryptedKey}))
        print('\n')

        # Step 6
        print('Step 6')
        data = pickle.loads(s.recv(1000))
        AESkey = crypto.Rsa().decrypt(data['encryptedKey'], key)
        pgResponseEncrypted = {
            'cipertext': data['pgResponse'][0],
            'nonce': data['pgResponse'][1],
            'tag': data['pgResponse'][2]
        }
        pgResponse = pickle.loads(crypto.Aes().decrypt(pgResponseEncrypted, AESkey))
        # verify PG signature
        print('Verify PG signature')
        msg = pickle.dumps({
            'resp': pgResponse['resp'],
            'sid': pgResponse['sid'],
            'amount': produse[produs],
            'nc': 1
        })
        crypto.Sign().verifySignature(msg, pgResponse['signedMessage'], publicKeyPG)
        print('Am primit raspunsul pentru tranzactie = ', pgResponse['resp'])

