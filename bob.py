from utils import money_order, client
import pickle
import copy

bob = client('bob')

# load alice's money order
with open('alice_money_order.pickle','rb') as f:
	alice_money_order = pickle.load(f)

# execution order that bob follows
PLAN = 2
        
# 0. plain and honest redemption of money order
if PLAN == 0:
        bob.redeem_money_order_at_bank(alice_money_order)

# 1. try to redeem the already redeemed money order at the Bank again
if PLAN == 1:
        bob_money_order = copy.deepcopy(alice_money_order)
        bob.redeem_money_order_at_bank(alice_money_order) # first try 
        
        bob.redeem_money_order_at_bank(bob_money_order) # second try

# 2. try increasing the amount in the money order
if PLAN == 2:
        # increase the original amount in the money order
        orig_money = alice_money_order.read_money()
        alice_money_order.write_money(orig_money+10) 

        bob.redeem_money_order_at_bank(alice_money_order) 
