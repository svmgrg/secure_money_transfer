from Crypto.Cipher import AES
import random
import copy
import socket
import pickle

class money_order(object):
    '''This class represents the functionality of the money order.

    It has a single data structure list by the name of 'order'.
    'order' has 3 attributes:
    1> random number representing transaction id of the money order.
    2> amount of the money order.
    3> digital signature by the bank for authentication.

    There are four functions and their functionality is same as their names suggest.
    '''
    
    def __init__(self):
        self.order = []
        self.order.append(int(10000*random.random()))
        self.order.append(0)
        self.order.append(None)


    def read_order_no(self):
        return self.order[0]
    
        
    def write_money(self, money):
        self.order[1] = money

        
    def read_money(self):
        return self.order[1]


    def write_sign(self, sign):
        self.order[2] = sign

        
    def read_sign(self):
        return self.order[2]

    
    @staticmethod
    def encrypt(order_obj, keys):
        '''This static function encrypts a money order with a 'keys' using the AES algorithm.
        The order_no and the order amount are encrypted, so that only the authorized user can
        view them.
        '''
        sec_key, init_vec = keys
        
        # encrypt order no
        order_no = order_obj.order[0]
        order_no = '0'*(16-len(str(order_no)))+str(order_no)
        cipher_obj = AES.new(sec_key, AES.MODE_CBC, init_vec)
        order_no = cipher_obj.encrypt(order_no)
        order_obj.order[0] = order_no

        # encrypt order amount
        amount = order_obj.order[1]
        amount = '0'*(16-len(str(amount)))+str(amount)
        cipher_obj = AES.new(sec_key, AES.MODE_CBC, init_vec)
        amount = cipher_obj.encrypt(amount)
        order_obj.order[1] = amount

        return order_obj

    
    @staticmethod
    def decrypt(order_obj, keys):
        '''This static function decrypts an encrypted money order with a 'keys' 
        using the AES algorithm.
        '''
        sec_key, init_vec = keys
        
        # encrypt order no
        order_no = order_obj.order[0]
        decipher_obj = AES.new(sec_key, AES.MODE_CBC, init_vec)
        order_no = decipher_obj.decrypt(order_no)
        order_no = int(order_no)
        order_obj.order[0] = order_no

        # encrypt order amount
        amount = order_obj.order[1]
        decipher_obj = AES.new(sec_key, AES.MODE_CBC, init_vec)
        amount = decipher_obj.decrypt(amount)
        amount = int(amount)
        order_obj.order[1] = amount

        return order_obj


class Bank(object):
    '''This class represents the functionality of the bank.
    It processes an object of the class 'money_order' using multiple functions as described below.
    '''
    
    def __init__(self, bank_name='Secure Bank'):
        
        print('Welcome to {0}.'.format(bank_name))
        self.bank_name = bank_name
        
        # secret bank key to verify the authenticity of bank signatures
        self.bank_sign = 32165535
        
        # nonce list to verify the freshness of bank signatures 
        self.ALL_NONCE = []
        self.messages_list = []
        self.secret_key = 'This is a key123'
        self.init_vector = 'This is an IV456'

        
    def _get_bank_signature(self, money):
        '''Function to generate bank signature to authenticate a money order.'''
        
        # generate bank signature
        bank_sign = self.bank_sign # secret bank key
        
        # nonce for freshness
        nonce = str(random.random()*1e12)
        if len(nonce) < 8:
            nonce = '0'*(8-len(nonce))+nonce
        else:
            nonce = nonce[0:8]
            
        # to encrypt amount requested by the money order
        if len(str(money)) < 16:
            money = '0'*(16-len(str(money)))+str(money)
            
        nonce_sign = str(bank_sign) + str(nonce) + money

        # encrypt this signature using library
        cipher_obj = AES.new(self.secret_key, AES.MODE_CBC, self.init_vector)
        nonce_sign_encrypted = cipher_obj.encrypt(nonce_sign)
        
        return nonce_sign_encrypted
   

    def get_empty_money_orders(self, num_orders=0):
        '''Function provides 'num_orders' empty money orders to clients.'''
        
        self.messages_list = []
        message = 'Welcome to {0}.'.format(self.bank_name)              
        self.messages_list.append(message)
        
        return [money_order() for i in range(num_orders)]


    def obtain_keys_for_money_orders(self, money_orders):
        '''This function saves the encrypted money orders received from the client and requests 
        keys for decrypting all but one money order in order to maintain client's anonymity.
        '''
        
        self.messages_list = [] 
        self.messages_list.append('Welcome to {0}. Processing money order -- stage 1'.format(
            self.bank_name))
        
        # randomly choose the single order which is not to be opened.
        order_dont_open = random.randint(0, len(money_orders)-1)

        # save the recieved money orders
        self.recv_money_orders = money_orders
        self.order_dont_open = order_dont_open

        return order_dont_open


    def process_money_orders(self, keys):
        '''This function accepts a list of keys and uses them to decrypt all but one previously
        obtained money orders. This gives the client an assurance that the main money order was
        not viewed by the bank; thus, ensuring anonymity of the client.
        It then verifies whether all the money orders contain the same amount of cash
        by randomly opening all but one money order.
        If all is correct, it signs the unopened money order and returns it to the client.
        '''
        
        self.messages_list = []
        self.messages_list.append('Welcome to {0}. Processing money order -- stage 2'.format(
            self.bank_name))           
        
        # decrypt the money orders using the keys received from the client
        money_orders = []
        for i in range(100):
            if i == self.order_dont_open:
                tmp = self.recv_money_orders[i]
            else:
                tmp = money_order.decrypt(self.recv_money_orders[i], keys[i])
            money_orders.append(tmp)

        # flag for checking if a valid set of money orders has been received by the bank
        MONEY_ORDER_CORRECTNESS = True
        # money_set variable is a set element that keeps count of the different requested amounts
        money_set = set()

        # check if the list of money orders received is valid
        for i in range(len(money_orders)):
            if money_orders[i].read_sign() != None:
                message = self._format_bank_message('Invalid set of money orders. Error: Money '
                                                    ' order is already signed.')                
                self.messages_list.append(message)
                
                return None
            
            if i == self.order_dont_open:
                continue

            # check if all the money orders till now have carried the same requested amount
            money = money_orders[i].read_money()
            money_set.add(money)
            # if not, set flag 'MONEY_ORDER_CORRECTNESS' to False
            if len(money_set) > 1:
                MONEY_ORDER_CORRECTNESS = False
                break

        # if the list of money orders received is valid, sign the unopened money order and return it
        if MONEY_ORDER_CORRECTNESS:
            # generate the encrypted bank signature
            money_in_order = list(money_set)[0]
            bank_signature = self._get_bank_signature(money_in_order)
            
            # pick the unnopened money order and sign it with an encrypted sign.
            money_orders[self.order_dont_open].write_sign(bank_signature)
            print('Money order is successfully processed.')
            self.messages_list.append('Money order is successfully processed.')
                        
            # deduct the amount from the Alice's account found in the opened money orders
            money_deducted = list(money_set)[0]
            print('Deducted Rs. {0} from Alice\'s account.'.format(money_deducted))
            self.messages_list.append('Deducted Rs. {0} from Alice\'s account.'.format(money_deducted))
                            
            return money_orders[self.order_dont_open]           
        else:
            self.messages_list.append('Invalid set of money orders. Error: All money orders'
                                      ' don\'t contain the same requested amount.')
            
            return None

    def redeem_money_order(self, money_order):
        '''This function accepts a money order.
        It then verifies whether the money order contains a fresh copy of a valid bank signature.
        If all is correct, it gives the bearer the amount request on the money order.
        '''
        
        self.messages_list = []             
        self.messages_list.append('Welcome to {0}.'.format(self.bank_name))
        
        # read the signature on the money_order
        money_order_sign = money_order.read_sign()

        # decrypt the signature
        decipher_obj = AES.new(self.secret_key, AES.MODE_CBC, self.init_vector)
        order_sign_decrypted = decipher_obj.decrypt(money_order_sign)

        # verify whether the secret bank signature key matches
        BANK_KEY_FLAG = True
        if self.bank_sign != int(order_sign_decrypted[0:8]):
            BANK_KEY_FLAG = False

        # verify whether the bank signature is fresh
        BANK_SIGN_FRESH = True
        # verify that the amount of money in sign matches amount of money requested in the money order
        MONEY_CHECK = True
        if BANK_KEY_FLAG:
            # check for nonce freshness
            added_nonce = int(order_sign_decrypted[8:16])
            if added_nonce in self.ALL_NONCE:
                BANK_SIGN_FRESH = False
            else:
                self.ALL_NONCE.append(added_nonce)
                
            # check if amount of money in sign matches amount of money requested in the money order
            money_in_sign = int(order_sign_decrypted[16:])
            if money_in_sign != money_order.read_money():
                MONEY_CHECK = False

        if not BANK_KEY_FLAG:
            # reject the money order
            self.messages_list.append('Invalid money order. Error: Money order is not authorized.')
        elif not BANK_SIGN_FRESH:
            # reject the money order
            self.messages_list.append('Invalid money order. Error: Money order is already redeemed.')
        elif not MONEY_CHECK:
            # reject the money order
            self.messages_list.append('Invalid money order. Error: Amount mentioned in the'
                                      ' money order doesn\'t match the amount for which the'
                                      ' money order was orginally authorized.')
        else:
            # accept the money order
            self.messages_list.append('Bank sign matched. The money order is accepted.')

            # credit the amount requested in the money order
            money_credited = money_order.read_money()
            self.messages_list.append(
                'Credited Rs. {0} to the merchant\'s account.'.format(money_credited))
 

class client(object):
    '''This class is used to create bank user and merchant object which can then communicate with 
    the bank server.
    '''
    
    def __init__(self, client_name='client1'):
        
        print('Welcome {0}.'.format(client_name))
         
    
    def _send_data(self, data_to_send):
        '''Transfers data to bank server.
        It first serializes the data using pickle.
        This serialized data (similar to a string) is transferred using socket.
        Data received from the server is then unserialized.
        '''

        # create sockets and initialize the details
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostname()
        self.port = 60009
        self.transmission_size = 65536
        
        self.client_socket.connect((self.host, self.port))
        
        self.client_socket.send(data_to_send) 
        
        recieved_data = ''
        recieved_data = self.client_socket.recv(self.transmission_size)
        return_object = None
        
        while recieved_data:
            recieved_data = pickle.loads(recieved_data)

            if(recieved_data[0] == 'msg'):
                print('Server--- {0}'.format(recieved_data[1]))
            elif(recieved_data[0] == 'object'):
                return_object = recieved_data[1] 
                
            recieved_data = self.client_socket.recv(self.transmission_size)
            
        self.client_socket.close()
        
        return return_object

    
    def get_empty_money_orders_from_bank(self, num_orders=0):
        data_to_send = ('get_empty_money_orders', num_orders)
        data_to_send = pickle.dumps(data_to_send)
        recieved_object = self._send_data(data_to_send) 
        money_orders = recieved_object
        
        return money_orders
       
    
    def process_money_orders_from_bank1(self, money_orders):
        '''This function delivers encrypted money orders to bank, 
        and returns the keys asked by bank to decrypt all but one money orders
        '''
        
        data_to_send = ('process_money_orders1', money_orders)
        data_to_send = pickle.dumps(data_to_send)
        recieved_object = self._send_data(data_to_send) 
        not_requested_key = recieved_object
        
        return not_requested_key

    
    def process_money_orders_from_bank2(self, keys):
        '''This function delivers the keys asked by bank,
        and returns the signed money order back to the user.
        '''
        
        data_to_send = ('process_money_orders2', keys)
        data_to_send = pickle.dumps(data_to_send)
        recieved_object = self._send_data(data_to_send) 
        signed_money_order = recieved_object
        
        return signed_money_order


    def redeem_money_order_at_bank(self, money_order):
        data_to_send =('redeem_money_order', money_order)
        data_to_send = pickle.dumps(data_to_send)
        self._send_data(data_to_send)

        
class server(object):
    '''This class is used to create object of the bank server.
    This bank server then communicates with the clients associated with bank user and merchant.
    '''
    
    def __init__(self, host=None, port=1234, transmission_size=1024, listen_request=5):
        
        self.port = port                   
        self.server_socket = socket.socket()
        # to counter -- OSError: [Errno 98] Address already in use
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.host = host    
        self.server_socket.bind((host, port))           
        self.server_socket.listen(listen_request)                    
        self.transmission_size = transmission_size
        print('Server configured; is ready to run.')
        
        self.bank = Bank()
        print('Server linked to bank.')
        
        
    def run(self):
        '''This function is the main socket which listens for, and serves request of the clients.
        Main purpose of this function is to call the specific functions of the bank class as requested 
        by the client.
        It first serializes the data using pickle.
        This serialized data (similar to a string) is transferred using socket.
        Data received from the server is then unserialized.
        '''
        
        print('Server listening ...')
        while True:
            conn, addr = self.server_socket.accept()    
            print('Got connection from ', addr)
            data_received = conn.recv(self.transmission_size)
            data_received = pickle.loads(data_received)
            request_type, data_arg = data_received
            data_to_send = None

            print('Server received request for {0}'.format(request_type))

            # call the specific functions given the client requests
            if request_type == 'get_empty_money_orders':
                data_to_send = self.bank.get_empty_money_orders(data_arg)        
                data_to_send = ('object', data_to_send)
            elif request_type == 'process_money_orders1':
                data_to_send = self.bank.obtain_keys_for_money_orders(data_arg)
                data_to_send = ('object', data_to_send)
            elif request_type == 'process_money_orders2':
                data_to_send = self.bank.process_money_orders(data_arg)
                data_to_send = ('object', data_to_send)
            elif request_type == 'redeem_money_order':
                data_to_send = self.bank.redeem_money_order(data_arg)
                data_to_send = ('msg', 'Submitted.')
            else:
                pass

            data_to_send = pickle.dumps(data_to_send)
            conn.send(data_to_send)
            for msg in self.bank.messages_list:
                print(msg)
                data_to_send = ('msg', msg)
                data_to_send = pickle.dumps(data_to_send)
                conn.send(data_to_send)

            data_to_send = ('msg', 'Thank you for connecting to {0}.'.format(self.bank.bank_name))
            data_to_send = pickle.dumps(data_to_send)
            conn.send(data_to_send)

            print('Sending completed.\n')

            conn.close()
