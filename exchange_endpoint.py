# from flask import Flask, request, g
# from flask_restful import Resource, Api
# from sqlalchemy import create_engine
# from flask import jsonify
# import json
# import eth_account
# import algosdk
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.orm import scoped_session
# from sqlalchemy.orm import load_only
# from datetime import datetime
# import math
# import sys
# import traceback

# # Generating key-pairs for the exchange on both the Ethereum and Algorand platforms
# # Checking to see if an order is accompanied by a payment into the Exchange’s account
# # Executing transactions on both blockchains when orders are matched (filled)
# # Recording the executed transactions in the table ‘TX’ (see models.py)

# # TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
# from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth
# from models import Base, Order, TX, Log
# engine = create_engine('sqlite:///orders.db')
# Base.metadata.bind = engine
# DBSession = sessionmaker(bind=engine)

# app = Flask(__name__)

# """ Pre-defined methods (do not need to change) """

# @app.before_request
# def create_session():
#     g.session = scoped_session(DBSession)

# @app.teardown_appcontext
# def shutdown_session(response_or_exc):
#     sys.stdout.flush()
#     g.session.commit()
#     g.session.remove()

# def connect_to_blockchains():
#     # connect to alg - 
#     try:
#         # If g.acl has not been defined yet, then trying to query it fails
#         acl_flag = False
#         g.acl
#     except AttributeError as ae:
#         acl_flag = True
    
#     try:
#         if acl_flag or not g.acl.status():
#             # Define Algorand client for the application
#             g.acl = connect_to_algo()
#     except Exception as e:
#         print("Trying to connect to algorand client again")
#         print(traceback.format_exc())
#         g.acl = connect_to_algo()
    
#     # connect to alg - indexer
#     try:
#         icl_flag = False
#         g.icl
#     except AttributeError as ae:
#         icl_flag = True
    
#     try:
#         if icl_flag or not g.icl.health():
#             # Define the index client
#             g.icl = connect_to_algo(connection_type='indexer')
#     except Exception as e:
#         print("Trying to connect to algorand indexer client again")
#         print(traceback.format_exc())
#         g.icl = connect_to_algo(connection_type='indexer')

#     # connect to eth
#     try:
#         w3_flag = False
#         g.w3
#     except AttributeError as ae:
#         w3_flag = True
    
#     try:
#         if w3_flag or not g.w3.isConnected():
#             g.w3 = connect_to_eth()
#     except Exception as e:
#         print("Trying to connect to web3 again")
#         print(traceback.format_exc())
#         g.w3 = connect_to_eth()
        
# """ End of pre-defined methods """
        
# """ Helper Methods (skeleton code for you to implement) """

# def log_message(message_dict):
#     msg = json.dumps(message_dict)

#     # TODO: Add message to the Log table
#     g.session.add(Log(message = msg))
#     g.session.commit()  # COMMIT THE MESSAGE
#     return

# def get_algo_keys():
    
#     # TODO: Generate or read (using the mnemonic secret) 
#     # the algorand public/private keys
#     algo_sk = 'im0WgwifTg2IBvCJOKPMbN3tTgVFdJFgsx/3Daw59+/g0hN9ZMsHylMfohEKtdTChX/agpu5cYtxnGFFdIHHnA=='
#     algo_pk = '4DJBG7LEZMD4UUY7UIIQVNOUYKCX7WUCTO4XDC3RTRQUK5EBY6OB3CNRS4'
#     # private_key = 'im0WgwifTg2IBvCJOKPMbN3tTgVFdJFgsx/3Daw59+/g0hN9ZMsHylMfohEKtdTChX/agpu5cYtxnGFFdIHHnA==' # using the generated private key as input
#     # address = '4DJBG7LEZMD4UUY7UIIQVNOUYKCX7WUCTO4XDC3RTRQUK5EBY6OB3CNRS4'  # using the generated address as input
    
#     return algo_sk, algo_pk


# def get_eth_keys(filename = "eth_mnemonic.txt"):
#     # w3 = Web3()
#     # w3 = web3.Web3()
#     # Account = w3.eth.account.create('put some extra entropy here')
#     # Address = myAccount.address
#     # myPrivateKey = myAccount.privateKey
#     # print('Public Key: {}'.format(myAccount.address))
#     # print('Private Key: {}'.format(myAccount.privateKey.hex()))
    
#     # TODO: Generate or read (using the mnemonic secret) 
#     # the ethereum public/private keys
#     eth_sk = '0xf1d1155d46e1a06a24d6e0ebb3384d7df5bae10f480079e43032f77e0a683881'
#     eth_pk = '0xDEB9f99bB530Fa37C4ad934C96280a3fc28a5219'

#     return eth_sk, eth_pk
  
# def fill_order(order, txes=[]):
#     # TODO: 
#     # Match orders (same as Exchange Server II)
#     # Validate the order has a payment to back it (make sure the counterparty also made a payment)
#     # Make sure that you end up executing all resulting transactions!
#     existing_order = g.session.query(Order).filter(Order.filled == None, Order.buy_currency == order.sell_currency, Order.sell_currency == order.buy_currency, ((Order.sell_amount / Order.buy_amount ) >= (order.buy_amount / order.sell_amount))).first()

#     # Match orders, if the existing match is found.
#     if existing_order != None:

#         # Set the filled field to be the current timestamp on both orders
#         order.filled = datetime.now()
#         existing_order.filled = datetime.now()

#         # Set counterparty_id to be the id of the other order
#         order.counterparty_id = existing_order.id
#         existing_order.counterparty_id = order.id

#         # If one of the orders is not completely filled (i.e. the counterparty’s sell_amount is less than buy_amount):

#         if existing_order.sell_amount < order.buy_amount or order.buy_amount < existing_order.sell_amount:
            
#             # new_order is the parent for the create_order
#             if existing_order.sell_amount < order.buy_amount:
                
#                 # id from parent order
#                 creator_id = order.id 
                
#                 # pk & platform from parent order
#                 sender_pk = order.sender_pk
#                 receiver_pk = order.receiver_pk
#                 buy_currency = order.buy_currency
#                 sell_currency = order.sell_currency

#                 # buy amount is the difference between the large order and small order
#                 buy_amount = order.buy_amount - existing_order.sell_amount

#                 # sell amount implies exchange rate of the new order is at least that of the old order
#                 exchange_rate = order.buy_amount / order.sell_amount
#                 sell_amount = buy_amount / exchange_rate
                
#             # existing_order is the parent for the create_order
#             else:
#                 # id from parent order
#                 creator_id = existing_order.id

#                 # pk & platform from parent order
#                 sender_pk = existing_order.sender_pk
#                 receiver_pk = existing_order.receiver_pk
#                 buy_currency = existing_order.buy_currency
#                 sell_currency = existing_order.sell_currency

#                 # sell amount is the difference between the large order and small order
#                 sell_amount = existing_order.sell_amount - order.buy_amount

#                 # buy amount implies exchange rate of the new order is at least that of the old order
#                 exchange_rate = existing_order.sell_amount / existing_order.buy_amount
#                 buy_amount = sell_amount / exchange_rate
                

#             # Create a new order for remaining balance
#             create_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, creator_id = creator_id)

#             g.session.add(create_order)
#             g.session.commit()
                
#         else:
#             g.session.commit()

#         # Check the payment
#         current_txe = {
#             'platform': order.buy_currency,'receiver_pk': order.receiver_pk, 'order_id': order.id, 'sell_amount' : order.sell_amount
#         }
#         txes.append(current_txe) # APPEND CURRENT TXE

#         existing_txe = {
#             'platform': existing_order.buy_currency,'receiver_pk': existing_order.receiver_pk, 'order_id': existing_order.id , 'sell_amount' : existing_order.buy_amount
#         }
#         txes.append(existing_txe) # APPEND EXISTING TXE

#         return txes
  
# def execute_txes(txes):
#     if txes is None:
#         return True
#     if len(txes) == 0:
#         return True
#     print( f"Trying to execute {len(txes)} transactions" )
#     print( f"IDs = {[tx['order_id'] for tx in txes]}" )
#     eth_sk, eth_pk = get_eth_keys()
#     algo_sk, algo_pk = get_algo_keys()
    
#     if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
#         print( "Error: execute_txes got an invalid platform!" )
#         print( tx['platform'] for tx in txes )

#     algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
#     eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

#     # TODO: 
#     #       1. Send tokens on the Algorand and eth testnets, appropriately
#     #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
#     #       2. Add all transactions to the TX table
    
#     # print('txes', txes)
#     # print(algo_txes)
#     # print(eth_txes)
    
#     # # Ethereum
#     # try:
#     #     eth_tx_ids = send_tokens_eth(g.w3, eth_sk, eth_txes)
#     # except Exception as e:
#     #     import traceback
#     #     print(traceback.format_exc())
#     #     print(e)

#     # for tx_id, tx in zip(eth_tx_ids, eth_txes):
#     #     txe = TX(platform="Ethereum", receiver_pk=tx['receiver_pk'], order_id=tx['order_id'], tx_id=tx['tx_id'])
#     #     try:
#     #         g.session.add(txe)
#     #     except Exception as e:
#     #         import traceback
#     #         print(traceback.format_exc())
#     #         print(e)
#     #     g.session.commit()

#     # # Algorand
#     # try:
#     #     alo_tx_ids = send_tokens_algo(g.acl, algo_sk, algo_txes)
#     # except Exception as e:
#     #     import traceback
#     #     print(traceback.format_exc())
#     #     print(e)

#     # for tx_id,tx in zip(alo_tx_ids, algo_txes):
#     #     txe = TX(platform="Ethereum", receiver_pk=tx['receiver_pk'], order_id=tx['order_id'], tx_id=tx['tx_id'])
#     #     g.session.add(txe)
#     #     g.session.commit()


#     if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
#         print( "Error: execute_txes got an invalid platform!" )
#         print( tx['platform'] for tx in txes )

#     algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
#     eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

#     # TODO: 
#     #       1. Send tokens on the Algorand and eth testnets, appropriately
#     #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
#     #       2. Add all transactions to the TX table
#     send_tokens_algo(g.acl, algo_sk, algo_txes)
#     send_tokens_eth(g.w3, eth_sk, eth_txes)
#     g.session.add_all(algo_txes)
#     g.session.add_all(eth_txes)
#     g.session.commit()

# def verify_sig(sig, payload):
        
#     sender_pk = payload['sender_pk'] # payload - sender_pk
#     platform = payload['platform'] # payload - platform
#     payload = json.dumps(payload)

#     # Case 1: Ethereum
#     if platform == 'Ethereum':
#         eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
#         if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == sender_pk:
#             result = True
#         else:
#             result = False

#     # Case 2: Algorand
#     elif platform == 'Algorand':
#         if algosdk.util.verify_bytes(payload.encode('utf-8'), sig, sender_pk):
#             result = True
#         else:
#             result = False
        
#     # Case 3: any other crypto platform
#     else:
#         result = False
#     return result

# """ End of Helper methods"""
  
# @app.route('/address', methods=['POST'])
# def address():
#     if request.method == "POST":
#         content = request.get_json(silent=True)
#         if 'platform' not in content.keys():
#             print( f"Error: no platform provided" )
#             return jsonify( "Error: no platform provided" )
#         if not content['platform'] in ["Ethereum", "Algorand"]:
#             print( f"Error: {content['platform']} is an invalid platform" )
#             return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
#         if content['platform'] == "Ethereum":
#             #Your code here
#             eth_sk, eth_pk = get_eth_keys()
#             return jsonify( eth_pk )
#         if content['platform'] == "Algorand":
#             #Your code here
#             algo_sk, algo_pk = get_algo_keys()
#             return jsonify( algo_pk )

# @app.route('/trade', methods=['POST'])
# def trade():
#     print( "In trade", file=sys.stderr )
#     connect_to_blockchains()
#     # get_keys()
#     if request.method == "POST":
#         content = request.get_json(silent=True)
#         columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
#         fields = [ "sig", "payload" ]
#         error = False
#         for field in fields:
#             if not field in content.keys():
#                 print( f"{field} not received by Trade" )
#                 error = True
#         if error:
#             print( json.dumps(content) )
#             return jsonify( False )
        
#         error = False
#         for column in columns:
#             if not column in content['payload'].keys():
#                 print( f"{column} not received by Trade" )
#                 error = True
#         if error:
#             print( json.dumps(content) )
#             return jsonify( False )
        
#         # Your code here
        
#         # 1. Check the signature
#         result = verify_sig(content['sig'], content['payload'])

#         if result == False:
#             log_message(content)
#             return jsonify(False)
        
#         # 2. Add the order to the table
#         else:
#             payload = content['payload']
#             signature = content['sig']

#             sender_pk = payload['sender_pk']
#             receiver_pk = payload['receiver_pk']
#             buy_currency = payload['buy_currency']
#             sell_currency = payload['sell_currency']
#             buy_amount = payload['buy_amount']
#             sell_amount = payload['sell_amount']
#             tx_id = payload['tx_id']
            
#             if buy_amount <= 0 or sell_amount <= 0 or receiver_pk is None:
#                 log_message(content)
#                 return jsonify(False)

#             else:
#         # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

#         # 3b. Fill the order (as in Exchange Server II) if the order is valid
#                 order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_currency, sell_currency=sell_currency, buy_amount=buy_amount, sell_amount=sell_amount, tx_id=tx_id, signature=signature)
#                 g.session.add(order)
#                 g.session.commit()
#                 current_txes = fill_order(order)
        
#         # 4. Execute the transactions
#                 # execute_txes(current_txes)
#             if sell_currency == 'Ethereum':
#                 tx = g.w3.eth.get_transaction(tx_id)
#                 assert tx.value == sell_amount
#             elif sell_currency == 'Algorand':
#                 tx = g.icl.search_transactions(txid=tx_id)
#                 assert tx.amoutn == sell_amount
#             else:
#                 pass
#             if (tx.platform!=tx.order.sell_currency or 
#                 sell_amount!=tx.order.sell_amount or 
#                 sender_pk!=tx.order.sender_pk or 
#                 0):
#                 return jsonify(False)
#             else:
#                 # 3b. Fill the order (as in Exchange Server II) if the order is valid
#                 pass
#                 # 4. Execute the transactions

#                 execute_txes(current_txes)
        
#         # If all goes well, return jsonify(True). else return jsonify(False)
#         if result == True:
#             return jsonify(True)
#         else:
#             return jsonify(False)

# @app.route('/order_book')
# def order_book():
#     fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
#     # Same as before
#     result = {'data': []}

#     for this in g.session.query(Order).all():
#         result['data'].append({'sender_pk': this.sender_pk,
#                                'receiver_pk': this.receiver_pk,
#                                'buy_currency': this.buy_currency,
#                                'sell_currency': this.sell_currency,
#                                'buy_amount': this.buy_amount,
#                                'sell_amount': this.sell_amount,
#                                'tx_id': this.tx_id,
#                                'signature': this.signature})

#     return jsonify(result)
#     # pass

# if __name__ == '__main__':
#     app.run(port='5002')







from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth, Web3, account, mnemonic

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log = Log(message=msg)
    g.session.add(log)
    g.session.commit()
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = 'range castle ring truth employ stomach merit capable tide quote jar oyster cross ordinary kite miracle satoshi paddle math shock today source repair abandon reunion'
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    # type(mnemonic) = str
    with open(filename,'r') as f:
        mnemonic = f.read().strip()
    eth_account.Account.enable_unaudited_hdwallet_features()
    acct = eth_account.Account.from_mnemonic(mnemonic)
    eth_pk = acct.address 
    eth_sk = acct.keys
    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

	# If your fill_order function is recursive, and you want to have fill_order return a list of transactions to be filled, 
	# Then you can use the "txes" argument to pass the current list of txes down the recursion
	# Note: your fill_order function is *not* required to be recursive, and it is *not* required that it return a list of transactions, 
	# but executing a group of transactions can be more efficient, and gets around the Ethereum nonce issue described in the instructions
    
    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    send_tokens_algo(g.acl, algo_sk, algo_txes)
    send_tokens_eth(g.w3, eth_sk, eth_txes)
    g.session.add_all(algo_txes)
    g.session.add_all(eth_txes)
    g.session.commit()
    
def check_sig(payload, sig):
    pk = payload.get('pk')
    if payload.get('platform') == 'Ethereum':
        encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        return eth_account.Account.recover_message(encoded_msg, signature=sig) == pk
    else:
        return algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            _, eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            _, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    # get_keys()
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        sig = content.get('sig')
        payload = content.get('payload')

        if check_sig(payload, sig): # successfully verified
            # 2. Add the order to the table in the database
            sender_pk = payload['sender_pk']
            receiver_pk = payload['receiver_pk']
            buy_currency = payload['buy_currency']
            sell_currency = payload['sell_currency']
            buy_amount = payload['buy_amount']
            sell_amount = payload['sell_amount']
            tx_id = payload['tx_id']
            order = Order(
                sender_pk=sender_pk, 
                receiver_pk=receiver_pk, 
                buy_currency=buy_currency,
                sell_currency=sell_currency,
                buy_amount=buy_amount,
                sell_amount=sell_amount,
                tx_id = tx_id,
            )
            g.session.add(order)
            g.session.commit()
            # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            if sell_currency == 'Ethereum':
                tx = g.w3.eth.get_transaction(tx_id)
                assert tx.value == sell_amount
            elif sell_currency == 'Algorand':
                tx = g.icl.search_transactions(txid=tx_id)
                assert tx.amoutn == sell_amount
            else:
                pass
            if (tx.platform!=tx.order.sell_currency or 
                sell_amount!=tx.order.sell_amount or 
                sender_pk!=tx.order.sender_pk or 
                0):
                return jsonify(False)
            else:
                # 3b. Fill the order (as in Exchange Server II) if the order is valid
                pass
                # 4. Execute the transactions
                execute_txes(txes)
        
        else: # not verified
            log_message(payload)
            return jsonify(False)
     
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    
    # Same as before
    order_list = []
    order_objects = g.session.query(Order).all()
    for order_obj in order_objects:
        order_dict = {}
        order_dict['sender_pk'] = order_obj.sender_pk
        order_dict['receiver_pk'] = order_obj.receiver_pk
        order_dict['buy_currency'] = order_obj.buy_currency
        order_dict['sell_currency'] = order_obj.sell_currency
        order_dict['buy_amount'] = order_obj.buy_amount
        order_dict['sell_amount'] = order_obj.sell_amount
        order_dict['signature'] = order_obj.signature
        order_dict['tx_id'] = order_obj.tx_id
        order_list.append(order_dict)

    return json.dumps(order_list)

if __name__ == '__main__':
    app.run(port='5002')
