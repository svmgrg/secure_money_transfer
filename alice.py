from utils import money_order, client
import pickle
import random
import copy

alice = client('alice')

alice_money_orders = alice.get_empty_money_orders_from_bank(num_orders=100)

# flag to check bank's response when Alice cheats
CHEAT = False

if not CHEAT:
    # fill up the requested amount in all the money orders
    money_requested = 1000
    for i in range(len(alice_money_orders)):
        alice_money_orders[i].write_money(money_requested)
else:
    # fill up the requested amount in all but one money orders 
    money_requested = 1000
    for i in range(len(alice_money_orders)):
        alice_money_orders[i].write_money(money_requested)

    # fill up extra amount in one random money order
    money_cheat = 10000
    cheat_index = random.randint(0, 99)
    alice_money_orders[cheat_index].write_money(money_cheat)

# generate 100 random keys for encrypting the money orders using AES algorithm
keys = []
for i in range(100):
    tmp1 = str(random.random())
    if len(tmp1) < 16:
        tmp1 = '0'*(16-len(tmp1))+str(tmp1)
    else:
        tmp1 = tmp1[0:16]

    tmp2 = str(random.random())
    if len(tmp2) < 16:
        tmp2 = '0'*(16-len(tmp2))+str(tmp2)
    else:
        tmp2 = tmp2[0:16]
    
    keys.append((tmp1, tmp2))

# encrypt the money orders so as to prevent the bank from opening them
encrypted_money_orders = [money_order.encrypt(alice_money_orders[i], keys[i]) for i in range(100)]

# get the money orders authorized from the bank

# 1. get the index of the requested keys from bank for opening all but one money orders
not_requested_key = alice.process_money_orders_from_bank1(encrypted_money_orders)

# 2. provide bank with the required keys and obtain the signed money order
main_key = copy.deepcopy(keys[not_requested_key])
keys[not_requested_key] = (0, 0)
signed_money_order = alice.process_money_orders_from_bank2(keys)

# 3. decrypt the signed money order so obtained so that it can be given to the merchant
if signed_money_order != None: # Alice did not cheat and thus received a signed money order
    signed_money_order = money_order.decrypt(signed_money_order, main_key)

    # save signed money order to disk so that it can be submitted to merchant
    with open('alice_money_order.pickle', 'wb') as f:
            alice_money_order = pickle.dump(signed_money_order, f)
