import datetime
import uuid
import socket
import crypto
import pickle

HOST, PORT = "localhost", 9009
filenameKey = 'pg-key.pem'
publicKeyServer = 'server-public.der'
publicKeyClient = 'client-public.der'
carduri = [
    {
        'cardN': b'0000111122223333',
        'cardExp': datetime.datetime(2020, 9, 10)
    },
    {
        'cardN': b'4444111122224444',
        'cardExp': datetime.datetime(2024, 5, 20)
    }
]

cardAmount = {
    carduri[0]['cardN']: 100,
    carduri[1]['cardN']: 40
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            # step 4
            data = pickle.loads(conn.recv(10000))

            key = crypto.Rsa().importKey(filenameKey)
            pubKM = crypto.Rsa().loadPublicKey(publicKeyServer)

            AESkeyM = crypto.Rsa().decrypt(data['encryptedKey'], key)
            print('Am decriptat MERCHANT AESkey = ', AESkeyM)
            encryptedMessage = {
                'cipertext': data['encryptedOrder'][0],
                'nonce': data['encryptedOrder'][1],
                'tag': data['encryptedOrder'][2]
            }
            order = pickle.loads(crypto.Aes().decrypt(encryptedMessage, AESkeyM))
            print('Order: ', order)
            # decrypt client message
            print('Decrypt client message')
            AESkeyC = crypto.Rsa().decrypt(order['encryptedPmKey'], key)
            print('Am decriptat CLIENT AESkey = ', AESkeyC)
            clientMessage = {
                'cipertext': order['pm'][0],
                'nonce': order['pm'][1],
                'tag': order['pm'][2]
            }
            clientOrder = pickle.loads(crypto.Aes().decrypt(clientMessage, AESkeyC))
            # verify client signature
            print('Verify client signature')
            if crypto.Sign().verifySignature(clientOrder['pi'], clientOrder['signedPi'], publicKeyClient) == False:
                print("Invalid signature, Closing the connection...")
                conn.close()
            pi = pickle.loads(clientOrder['pi'])
            # verify merchant signature
            mm = pickle.dumps({
                'sid': pi['sid'],
                'pubKC': pi['pubKC'],
                'amount': pi['amount']
            })
            print('Verify merchant signature')
            if crypto.Sign().verifySignature(mm, order['signedMm'], publicKeyServer) == False:
                print("Invalid signature, Closing the connection...")
                conn.close()

            # step 5
            print('Step 5')
            # verify client CARD
            clientNonce = pi['nc']
            resp = 'OK'
            if {'cardN': pi['cardN'], 'cardExp': pi['cardExp']} not in carduri:
                resp = 'Invalid card'
                print(resp)
            else:
                if cardAmount[pi['cardN']] < pi['amount']:
                    resp = 'Insuficient founds'
                    print(resp)
                else:
                    # modify account balance
                    cardAmount[pi['cardN']] -= pi['amount']
                    resp = resp + '\tCard Balance: ' + str(cardAmount[pi['cardN']])

            signedMessage = crypto.Sign().sign(pickle.dumps(
                {'resp': resp,
                 'sid': pi['sid'],
                 'amount': pi['amount'],
                 'nc': clientNonce}
            ), filenameKey)
            transactionInfo = pickle.dumps({
                'resp': resp,
                'sid': pi['sid'],
                'signedMessage': signedMessage
            })
            encryptedTransactionInfo = crypto.Aes().encrypt(transactionInfo, AESkeyM)
            encryptedKey = crypto.Rsa().encrypt(AESkeyM, pubKM)
            conn.sendall(pickle.dumps({'encryptedTransactionInfo': encryptedTransactionInfo,
                                       'encryptedKey': encryptedKey}))
            print('Am trimis informatii tranzactie criptate cu MERCHANT AESkey = ', AESkeyM,
                  '     MERCHANT RSA pubKM = ', pubKM.exportKey())
            conn.close()
            break
