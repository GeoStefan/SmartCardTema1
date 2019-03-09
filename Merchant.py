import socketserver
import uuid
import socket
import json
import crypto
import pickle

produse = {
    "item1": 20,
    "item2": 130,
    "item3": 25
}

HOST, PORT = "localhost", 8999
filename = 'server-key.pem'
publicKeyClient = 'client-public.der'
publicKeyPG = 'pg-public.der'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            # Trimite lista cu produse
            conn.sendall(pickle.dumps(produse))

            key = crypto.Rsa().importKey(filename)

            # setup sub-protocol
            # step 1
            print('Step 1')
            data = pickle.loads(conn.recv(10000))
            AESkey = crypto.Rsa().decrypt(data['key'], key)
            pubKCneimported = crypto.Aes().decrypt(data, AESkey)
            pubKC = crypto.Rsa().importKey2(pubKCneimported)
            print('Am primit CLIENT AESkey = ', AESkey, '    CLIENT RSA pubKC =', pubKC.exportKey(), '\n')

            # step 2
            print('Step 2')
            SID = uuid.uuid4().bytes
            signedSID = crypto.Sign().sign(SID, filename)
            encryptedMessage = crypto.Aes().encrypt(pickle.dumps({'sid': SID, 'signedSid': signedSID}), AESkey)
            encryptedKey = crypto.Rsa().encrypt(AESkey, pubKC)
            conn.sendall(pickle.dumps({'cipertext': encryptedMessage}))
            print('Am trimis SID = ', SID, '\n')

            # exchange sub-protocol
            # step 3
            print('Step 3')
            data = pickle.loads(conn.recv(20000))
            # trec peste decriptarea keyAES
            AESkey = crypto.Rsa().decrypt(data['encryptedKey'], key)
            print(AESkey)
            message = {
                'cipertext': data['encryptedMessage'][0],
                'nonce': data['encryptedMessage'][1],
                'tag': data['encryptedMessage'][2]
            }
            message = pickle.loads(crypto.Aes().decrypt(message, AESkey))
            # verify client signature on PO
            if crypto.Sign().verifySignature(message['po']['poContent'], message['po']['signedPo'], publicKeyClient):
                print("Correct signature")
            else:
                print("Invalid signature, Closing the connection...")
                conn.close()
            poContent = pickle.loads(message['po']['poContent'])
            # verify SID
            if SID != poContent['sid']:
                print('Invalid SID')
            # verify amount
            if produse[poContent['orderDesc']] != poContent['amount']:
                print('Invalid amount or product')
            print('\n')

            print('Step 4')
            # step 4
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spg:
                PGHOST = 'localhost'
                PGPORT = 9009
                spg.connect((PGHOST, PGPORT))
                print('M-am conectat la PaymentGateaway')

                AESkeyPG = b'0123456789123499'
                pubPG = crypto.Rsa().loadPublicKey(publicKeyPG)

                merchantMessage = pickle.dumps({
                    'sid': SID,
                    'pubKC': pubKCneimported,
                    'amount': produse[poContent['orderDesc']]
                })
                signedMessage = crypto.Sign().sign(merchantMessage, filename)

                order = pickle.dumps({
                    'pm': message['encryptedPm'],
                    'encryptedPmKey': message['encryptedPGkey'],
                    'mm': merchantMessage,
                    'signedMm': signedMessage
                })
                encryptedOrder = crypto.Aes().encrypt(order, AESkeyPG)
                encryptedKey = crypto.Rsa().encrypt(AESkeyPG, pubPG)

                spg.sendall(pickle.dumps({'encryptedOrder': encryptedOrder,
                                          'encryptedKey': encryptedKey}))
                print('Am trimis intregul mesaj criptat cu PG AESkey = ', AESkeyPG, '      PG RSA pubPG = ',
                      pubPG.exportKey(), '\n')

                # step 5
                print('Step 5')
                data = pickle.loads(spg.recv(10000))
                print(data)
                # trec peste verificare cheie
                encryptedTransactionInfo = {
                    'cipertext': data['encryptedTransactionInfo'][0],
                    'nonce': data['encryptedTransactionInfo'][1],
                    'tag': data['encryptedTransactionInfo'][2]
                }
                pgResponseBinary = crypto.Aes().decrypt(encryptedTransactionInfo, AESkeyPG)
                pgResponse = pickle.loads(pgResponseBinary)
                print('Am primit raspunsul ', pgResponse['resp'], ' pentru comunicarea cu SID = ', pgResponse['sid'],
                      '\n')

                # step 6
                print('Step 6')
                pgResponseBinary = crypto.Aes().encrypt(pgResponseBinary, AESkey)
                encryptedKey = crypto.Rsa().encrypt(AESkey, pubKC)
                conn.sendall(pickle.dumps({'pgResponse': pgResponseBinary,
                                           'encryptedKey': encryptedKey}))
                print('Am criptat si am trimis raspunsul de la PG la Client')
                spg.close()
            conn.close()
            break
