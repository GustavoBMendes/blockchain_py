'''
title           : client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Gustavo Belançon Mendes
date_created    : 20180212
date_modified   : 20180309
version         : 1.0
usage           : python client.py
                  python client.py -p 8080
                  python client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template

class Transaction:

	def __init__(self, sender_address, sender_private_key, recipient_address, value):
		self.sender_address = sender_address
		self.sender_private_key = sender_private_key
		self.recipient_address = recipient_address
		self.value = value

	def __getattr__(self, attr):
		return self.data[attr]

	def to_dict(self):
		#coleta os dados da transação e insere no formato dicionário
		return OrderedDict({'sender_address': self.sender_address,
							'recipient_address': self.recipient_address,
							'value': self.value
		})

#inicia a pagina web
app = Flask(__name__)

#rota para a pagina inicial
@app.route('/')
def index():
	return render_template('./index.html')

#rota para a aba de criação de transações
@app.route('/make/transaction')
def make_transaction():
	return render_template('./make_transaction.html')

#rota para a aba de consulta de transações
def view_transaction():
	return render_template('./view_transactions.html')

#método para execução da criação da carteira (chave pública e privada)
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()
	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}

#método para a publicação de uma transação na rede
@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():

	sender_address = request.form['sender_address'] #public_key
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['recipient_address'] #recipient public_key
	value = request.form['amount']

	transaction = Transaction(sender_address, sender_private_key, recipient_address, value)
	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200

if __name__ == '__main__':
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
	args = parser.parse_args()
	port = args.port

	app.run(host='127.0.0.1', port=port)