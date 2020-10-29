
# coding: utf-8

# In[39]:


import binascii

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from urllib.parse import urlparse
from argparse import ArgumentParser
from hashlib import sha256
import json
import time

from flask import Flask, request, render_template,jsonify
from flask_cors import CORS
import requests
from collections import OrderedDict


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = 0

    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid_proof(self, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    def proof_of_work(self, block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []
        return new_block.index

    #função para verificar chave privada de quem está iniciando a transação
    def assinar_transacao(self, transacao, chave_privada):
        try:
            privKey = RSA.importKey(binascii.unhexlify(chave_privada))
            assinatura = PKCS1_v1_5.new(privKey)
            h0 = SHA.new(str(transacao).encode('utf8'))
            return binascii.hexlify(assinatura.sign(h0)).decode('ascii')
        except:
            print('Chave privada não foi validada!')

    def verificar_assinatura(self, transacao, chave_publica, assinatura):
        try:
            pubKey = RSA.importKey(binascii.unhexlify(chave_publica))
            verifica = PKCS1_v1_5.new(pubKey)
            h = SHA.new(str(transacao).encode('utf8'))
            return verifica.verify(h, binascii.unhexlify(assinatura))
        except:
            print('Assinatura da transação não foi validada!')
    

app = Flask(__name__)
CORS(app)
blockchain = Blockchain()


# In[41]:

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/nova_transacao')
def nova_transacao():
    return render_template('./fazer_transacao.html')

@app.route('/minerar')
def page_minerar():
    return render_template('./minerar.html')

@app.route('/consultar_transacoes')
def consultar_transacoes():
    return render_template('./consulta.html')

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    #print(chain_data[0]['timestamp'])

    response = {
        'length': len(chain_data),
        'chain': chain_data
    }

    return jsonify(response), 200


# In[45]:

@app.route('/carteira', methods=['GET'])
def gerar_carteira():
    random_key = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_key)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200

@app.route('/block', methods=['GET'])
def get_lastblock():
    lb = []
    block = blockchain.chain[-1]
    lb.append(block.__dict__)
    return json.dumps({'lastblock': lb})

@app.route('/get_transactions', methods=['GET']) 
def get_transactions():
    transacoes = blockchain.unconfirmed_transactions
    response = {
        'transacoes': transacoes
    }
    return jsonify(response), 200

@app.route('/gerar_transacao', methods=['POST'])
def new_transaction():

    values = request.form
    info_necessaria = ['sender_address',  'sender_private_key', 'recipient_address', 'amount']
    if not all(k in values for k in info_necessaria):
        print('Faltando info')
        return 'Faltando informações', 400

    transaction = dict()

    transaction['sender_address'] = request.form['sender_address']
    transaction['recipient_address'] = request.form['recipient_address'],
    transaction['amount'] = request.form['amount']

    #copia da transacao para nao alterar o dict transaction
    dict_verf = OrderedDict({ 'sender_address': values['sender_address'], 'recipient_address': values['recipient_address'], 'amount': values['amount'] })

    #gerar assinatura da transacao
    digital_sign = blockchain.assinar_transacao(dict_verf, values['sender_private_key'])
    
    #verificar assinatura da transacao
    verificador = blockchain.verificar_assinatura(dict_verf, values['sender_address'], digital_sign)

    if verificador == True:

        transaction['assinatura'] = digital_sign

        print('Transação gerada')
        blockchain.add_new_transaction(transaction)
        response = {
            'sender_address': values['sender_address'],
            'recipient_address': values['recipient_address'],
            'amount': values['amount'],
            'assinatura': digital_sign
        }

        return jsonify(response), 201

    else:
        response={'message': 'Assinatura inválida!'}
        return jsonify(response), 406
    #return json.dumps({'newTransaction': blockchain.unconfirmed_transactions})

@app.route('/mine', methods=['GET']) 
def mine_transactions():

    #incluir processo de verificação da assinatura digital por meio da chave primária
    newblock = blockchain.mine()

    return json.dumps({'block': newblock})

parser = ArgumentParser()
parser.add_argument('-p', '--port', default=5000, type=int, help='porta a ser utilizada')
args = parser.parse_args()
port = args.port
app.run(host='127.0.0.1', debug=True, port=port)
