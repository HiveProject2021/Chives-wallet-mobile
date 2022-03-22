import json
import time
import asyncio
import aiosqlite
import sqlite3
import logging
import redis
import base64
import hashlib
import random

from typing import Dict, List, Optional

from blspy import AugSchemeMPL, G2Element, PrivateKey

from chia.consensus.constants import ConsensusConstants
from chia.util.hash import std_hash
from chia.types.announcement import Announcement
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_spend import CoinSpend
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.condition_with_args import ConditionWithArgs
from chia.types.spend_bundle import SpendBundle
from chia.util.clvm import int_from_bytes, int_to_bytes
from chia.util.condition_tools import conditions_by_opcode, conditions_for_solution, pkm_pairs_for_conditions_dict
from chia.util.ints import uint32, uint64
from chia.util.byte_types import hexstr_to_bytes


from chia.types.blockchain_format.classgroup import ClassgroupElement
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.foliage import TransactionsInfo
from chia.types.blockchain_format.program import SerializedProgram
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.blockchain_format.slots import InfusedChallengeChainSubSlot
from chia.types.blockchain_format.vdf import VDFInfo, VDFProof
from chia.types.end_of_slot_bundle import EndOfSubSlotBundle
from chia.types.full_block import FullBlock
from chia.types.unfinished_block import UnfinishedBlock

from chia.wallet.derive_keys import master_sk_to_wallet_sk
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
    solution_for_conditions,
)
from chia.wallet.puzzles.puzzle_utils import (
    make_assert_aggsig_condition,
    make_assert_coin_announcement,
    make_assert_puzzle_announcement,
    make_assert_relative_height_exceeds_condition,
    make_assert_absolute_height_exceeds_condition,
    make_assert_my_coin_id_condition,
    make_assert_absolute_seconds_exceeds_condition,
    make_assert_relative_seconds_exceeds_condition,
    make_create_coin_announcement,
    make_create_puzzle_announcement,
    make_create_coin_condition,
    make_reserve_fee_condition,
    make_assert_my_parent_id,
    make_assert_my_puzzlehash,
    make_assert_my_amount,
)
from chia.util.keychain import Keychain, bytes_from_mnemonic, bytes_to_mnemonic, generate_mnemonic, mnemonic_to_seed

from chia.consensus.default_constants import DEFAULT_CONSTANTS

from chia.rpc.full_node_rpc_api import FullNodeRpcApi
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.config import load_config
from chia.util.ints import uint16
from chia.util.misc import format_bytes

#转账的第三个版本,支持从REDIS中读取要转账的订单数据,进行转账,然后把结果写回入到REDIS.
#每次运行,最多支持五次转账记录,止到下次执行.
#后续程序再进行优化.

class WalletTool:
    next_address = 0
    pubkey_num_lookup: Dict[bytes, uint32] = {}

    def __init__(self, constants: ConsensusConstants, sk: Optional[PrivateKey] = None):
        
        
        self.constants = constants
        self.current_balance = 0
        self.my_utxos: set = set()
        self.generator_lookups: Dict = {}
        self.puzzle_pk_cache: Dict = {}
        self.puzzle_hash_to_private_key: Dict = {}
        
        #print(constants)
        #print()
        #print()
        #print()
     
    async def  push_transaction(self):  
        #得到REDIS中需要待发送的任务清单
        
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        CHIVES_WALLET_TX_DOING_CHIA = r.hgetall("CHIVES_WALLET_TX_DOING_CHIA")
        for ORDER_KEY,ORDER_STATUS in CHIVES_WALLET_TX_DOING_CHIA.items():
            #print(type(ORDER_STATUS))
            #print(type("READY"))
            if(ORDER_STATUS == bytes("READY","ascii") ):
                TODO_ORDER = r.hget("CHIVES_WALLET_TX_CHIA",ORDER_KEY)
                #防止TODO_ORDER在某些情况下面为 b''
                if TODO_ORDER is not None and len(TODO_ORDER)>10:
                    TODO_ORDER_64 = base64.b64decode(TODO_ORDER)
                    print('===================')
                    print(ORDER_KEY)
                    print('===================')
                    #print(TODO_ORDER)
                    print('===================')
                    #print(TODO_ORDER_64)
                    print('===================')
                    TODO_ORDER_JSON = json.loads(TODO_ORDER_64)
                    #print(TODO_ORDER_JSON)
                    print('===================')
                    if TODO_ORDER_64 is None:
                        TODO_ORDER_JSON = json.loads(TODO_ORDER_64)
                        TODO_ORDER_JSON = {}
                        TODO_ORDER_JSON['TX_STATUS'] 			= "FAIL";
                        TODO_ORDER_JSON['TX_RESULT'] 			= "Data Lost";
                        TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                        TODO_ORDER_JSON['TX_PATH'] 			    = "PYTHON";
                        print("EXCEPT-120-Data Lost")                    
                        #把执行以后的状态写入REDIS
                        TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                        TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                        #print(TODO_ORDER_JSON_TEXT)
                        #print(TODO_ORDER_64_TEXT)
                        #TODO_ORDER = r.hset("CHIVES_WALLET_TX_DOING_CHIA",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                        #TODO_ORDER = r.hset("CHIVES_WALLET_TX_CHIA",ORDER_KEY,TODO_ORDER_64_TEXT)
                    else:
                        print('===================')
                        TODO_ORDER_JSON = json.loads(TODO_ORDER_64)
                        print('===================')
                        print(ORDER_KEY)
                        print(ORDER_STATUS)
                        #print(TODO_ORDER_JSON)
                        #手工输入来构建参数部分代码
                        SendToAmount = uint64(TODO_ORDER_JSON['SEND_TO_AMOUNT'])
                        SendToPuzzleHash = TODO_ORDER_JSON['SEND_TO_PUZZLEHASH']
                        #设置交易平台手续的部分                
                        SendToAmountSwap = uint64(TODO_ORDER_JSON['SEND_TO_AMOUNT_SWAP'])
                        SendToPuzzleHashSwap = TODO_ORDER_JSON['SEND_TO_PUZZLEHASH_SWAP']
                        #设置找零地址,找零金额自动生成
                        CHANGE_PUZZLEHASH = TODO_ORDER_JSON['CHANGE_PUZZLEHASH']
                        #设置找零的数量,可以实现拆分为任意数量的零钱
                        CHANGE_NUMBER = uint64(TODO_ORDER_JSON['CHANGE_NUMBER'])
                        fee = uint64(TODO_ORDER_JSON['SEND_TO_MININGFEE'])
                        #fee = uint64(0)
                        #得到PRIMARY KEY
                        #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
                        coinList = []
                        DEPOSIT_COINS = TODO_ORDER_JSON['DEPOSIT_COINS']
                        if len(DEPOSIT_COINS) > 500:
                            TODO_ORDER_JSON = {}
                            TODO_ORDER_JSON['TX_STATUS'] 			= "FAIL";
                            TODO_ORDER_JSON['TX_RESULT'] 			= "Data Lost";
                            TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                            TODO_ORDER_JSON['TX_PATH'] 			    = "PYTHON";
                            print("EXCEPT-120-Data Lost")                    
                            #把执行以后的状态写入REDIS
                            TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                            TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                        else:
                            for row in DEPOSIT_COINS:
                                #print(row)
                                coin = Coin(hexstr_to_bytes(row['coin_parent']), hexstr_to_bytes(row['puzzle_hash']), uint64(row['amount']))
                                coinList.append(coin)
                                #形成PUZZLE_HASH到private_key的MAP
                                puzzle_hash_coin = hexstr_to_bytes(row['puzzle_hash'])
                                #得到每一个地址对应的私钥的MAP
                                self.puzzle_hash_to_private_key[puzzle_hash_coin] = row
                            print(self.puzzle_hash_to_private_key)
                            print(coinList)
                            #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
                            generate_signed_transaction = self.generate_signed_transaction_multiple_coins(
                                SendToAmount,
                                SendToPuzzleHash,
                                SendToAmountSwap,
                                SendToPuzzleHashSwap,
                                CHANGE_PUZZLEHASH,
                                CHANGE_NUMBER,
                                coinList,
                                {},
                                fee,
                            )
                            print(generate_signed_transaction)
                            #提交交易记录到区块链网络
                            SuccessText = False
                            try:
                                config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
                                self_hostname = config["self_hostname"]
                                rpc_port = config["full_node"]["rpc_port"]
                                client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
                                push_res = await client_node.push_tx(generate_signed_transaction)
                                print(push_res)
                                SuccessText = True
                                TODO_ORDER_JSON['TX_STATUS'] 			= "DONE";
                                TODO_ORDER_JSON['TX_RESULT'] 			= push_res['status'];
                                TODO_ORDER_JSON['TX_ID'] 			    = str(generate_signed_transaction.name());
                                TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                                TODO_ORDER_JSON['TX_PATH'] 			    = "PYTHON";
                                print("TRY-FFFFFFFFFFFFFFFFFFFFF")
                                #把执行以后的状态写入REDIS
                                TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                                TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                                print(TODO_ORDER_JSON_TEXT)
                                print(TODO_ORDER_64_TEXT)
                                TODO_ORDER = r.hset("CHIVES_WALLET_TX_DOING_CHIA",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                                TODO_ORDER = r.hset("CHIVES_WALLET_TX_CHIA",ORDER_KEY,TODO_ORDER_64_TEXT)
                            except Exception as ResultError:
                                print("EXCEPT-+++++++++++++++++++++++++")
                                #输出原始的错误内容.
                                print(ResultError)
                                #ResultErrorJson = json.loads(hexstr_to_bytes(ResultError))
                                ErrorText = ResultError.args[0]['error']
                                SuccessText = ResultError.args[0]['success']
                                if(ErrorText.find("DOUBLE_SPEND") > 0) :
                                    SuccessText = True
                                    TODO_ORDER_JSON['TX_STATUS'] 			= "DOUBLE_SPEND";
                                    TODO_ORDER_JSON['TX_RESULT'] 			= ErrorText;
                                    TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                                    TODO_ORDER_JSON['TX_PATH'] 			    = "PYTHON";
                                    print("EXCEPT-TTTTTTTTTTTTTTTTTTTTT")
                                else:
                                    TODO_ORDER_JSON['TX_STATUS'] 			= "FAIL";
                                    TODO_ORDER_JSON['TX_RESULT'] 			= ErrorText;
                                    TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                                    TODO_ORDER_JSON['TX_PATH'] 			    = "PYTHON";
                                    print("EXCEPT-FFFFFFFFFFFFFFFFFFFFF")
                                
                                #把执行以后的状态写入REDIS
                                TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                                TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                                #print(TODO_ORDER_JSON_TEXT)
                                #print(TODO_ORDER_64_TEXT)
                                TODO_ORDER = r.hset("CHIVES_WALLET_TX_DOING_CHIA",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                                TODO_ORDER = r.hset("CHIVES_WALLET_TX_CHIA",ORDER_KEY,TODO_ORDER_64_TEXT)
                            finally:
                                client_node.close()
                                await client_node.await_closed()
                            #不做人为中断的话,就可以循环执行,初期测试一下压力,可以不做判断.
                            #后期为了程序稳定,考虑到定时任务每一分钟执行的间隔,所以每一个进程需要在一分钟内完成,所以要求每次执行的数量尽量控制在5-10个TX记录.
                            #break
        
        
        #关闭REDIS连接
        r.connection_pool.disconnect()
        
        
        
        #print("===================================================")        
        #ResultStr = str(generate_signed_transaction)
        #ResultStrValue = ResultStr.replace("\'","\"")
        #print("curl --insecure --cert ~/.chives/mainnet/config/ssl/full_node/private_full_node.crt --key ~/.chives/mainnet/config/ssl/full_node/private_full_node.key -d '{        \"spend_bundle\":")
        #print(ResultStrValue)
        #print("}' -H \"Content-Type: application/json\" -X POST https://localhost:9755/push_tx")
        #print("===================================================")   
    
    async def GetAllAddress(self):    
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("~/.chives/mainnet/db/blockchain_v1_mainnet.sqlite")
        
        cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", (coin_name,))
        row = await cursor.fetchone()
        await cursor.close() 
    
    async def GetAllUnSpentCoins(self):    
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("~/.chives/mainnet/db/blockchain_v1_mainnet.sqlite")
        
        cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", (coin_name,))
        row = await cursor.fetchone()
        await cursor.close()  
        
    async def push_tx(self,generate_signed_transaction):
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx(generate_signed_transaction)
            print(push_res)
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
        
            
    def get_next_address_index(self) -> uint32:
        self.next_address = uint32(self.next_address + 1)
        return self.next_address

    def get_private_key_for_puzzle_hash(self, puzzle_hash: bytes32) -> PrivateKey:
        if puzzle_hash in self.puzzle_pk_cache:
            child = self.puzzle_pk_cache[puzzle_hash]
            private = master_sk_to_wallet_sk(self.private_key, uint32(child))
            #  pubkey = private.get_g1()
            return private
        else:
            for child in range(0,300):
                pubkey = master_sk_to_wallet_sk(self.private_key, uint32(child)).get_g1()
                #print(type(puzzle_hash))
                #print(type(puzzle_for_pk(bytes(pubkey)).get_tree_hash()))
                #print(puzzle_hash)
                if puzzle_hash == puzzle_for_pk(bytes(pubkey)).get_tree_hash():
                    #print('===================')
                    return master_sk_to_wallet_sk(self.private_key, uint32(child))
        raise ValueError(f"Do not have the keys for puzzle hash {puzzle_hash}")

    def puzzle_for_pk(self, pubkey: bytes) -> Program:
        return puzzle_for_pk(pubkey)

    def get_new_puzzle(self) -> bytes32:
        next_address_index: uint32 = self.get_next_address_index()
        pubkey = master_sk_to_wallet_sk(self.private_key, next_address_index).get_g1()
        self.pubkey_num_lookup[bytes(pubkey)] = next_address_index

        puzzle = puzzle_for_pk(bytes(pubkey))

        self.puzzle_pk_cache[puzzle.get_tree_hash()] = next_address_index
        return puzzle

    def get_new_puzzlehash(self) -> bytes32:
        puzzle = self.get_new_puzzle()
        return puzzle.get_tree_hash()

    def sign(self, value: bytes, pubkey: bytes) -> G2Element:
        privatekey: PrivateKey = master_sk_to_wallet_sk(self.private_key, self.pubkey_num_lookup[pubkey])
        return AugSchemeMPL.sign(privatekey, value)

    def make_solution(self, condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]]) -> Program:
        ret = []

        for con_list in condition_dic.values():
            for cvp in con_list:
                if cvp.opcode == ConditionOpcode.CREATE_COIN:
                    ret.append(make_create_coin_condition(cvp.vars[0], cvp.vars[1], None))
                if cvp.opcode == ConditionOpcode.CREATE_COIN_ANNOUNCEMENT:
                    ret.append(make_create_coin_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT:
                    ret.append(make_create_puzzle_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.AGG_SIG_UNSAFE:
                    ret.append(make_assert_aggsig_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT:
                    ret.append(make_assert_coin_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT:
                    ret.append(make_assert_puzzle_announcement(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_SECONDS_ABSOLUTE:
                    ret.append(make_assert_absolute_seconds_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_SECONDS_RELATIVE:
                    ret.append(make_assert_relative_seconds_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_COIN_ID:
                    ret.append(make_assert_my_coin_id_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE:
                    ret.append(make_assert_absolute_height_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_HEIGHT_RELATIVE:
                    ret.append(make_assert_relative_height_exceeds_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.RESERVE_FEE:
                    ret.append(make_reserve_fee_condition(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_PARENT_ID:
                    ret.append(make_assert_my_parent_id(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_PUZZLEHASH:
                    ret.append(make_assert_my_puzzlehash(cvp.vars[0]))
                if cvp.opcode == ConditionOpcode.ASSERT_MY_AMOUNT:
                    ret.append(make_assert_my_amount(cvp.vars[0]))
        return solution_for_conditions(Program.to(ret))

    def generate_unsigned_transaction(
        self,
        amount: uint64,
        to_puzzle_hash: bytes32,
        amount_swap: uint64,
        to_puzzle_hash_swap: bytes32,
        change_puzzle_hash: bytes32,
        change_number: uint64,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]],
        fee: int = 0,
        secret_key: Optional[PrivateKey] = None,
    ) -> List[CoinSpend]:
        spends = []
        print("======================")
        print(coins)
        print("======================")
        spend_value = sum([c.amount for c in coins])

        if ConditionOpcode.CREATE_COIN not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN] = []
        if ConditionOpcode.CREATE_COIN_ANNOUNCEMENT not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT] = []
        
        #转账金额
        output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(to_puzzle_hash), int_to_bytes(amount)])
        condition_dic[output.opcode].append(output)
        #得到找零金额
        #amount_total = sum(int_from_bytes(cvp.vars[1]) for cvp in condition_dic[ConditionOpcode.CREATE_COIN])
        change = spend_value - amount - amount_swap - fee
        if change > 0:
            if change_number > 1:
                #处理N-1个找零地址
                SubNumberTotal = 0
                for i in range(change_number - 1): 
                    SubNumber = uint64( uint64(change / change_number ) - random.randrange(1000000) )
                    SubNumberTotal = SubNumberTotal + SubNumber
                    #print(SubNumber)
                    output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(change_puzzle_hash), int_to_bytes(SubNumber)])
                    condition_dic[output.opcode].append(output)
                #处理最后一个找零的金额
                LastChangeAmount = change - SubNumberTotal
                output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(change_puzzle_hash), int_to_bytes(LastChangeAmount)])
                condition_dic[output.opcode].append(output)
            if change_number <= 1:
                output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(change_puzzle_hash), int_to_bytes(change)])
                condition_dic[output.opcode].append(output)
        #处理交易平台SWAP的手续费部分
        if amount_swap > 0:
            output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(to_puzzle_hash_swap), int_to_bytes(amount_swap)])
            condition_dic[output.opcode].append(output)  
            
        secondary_coins_cond_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = dict()
        secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT] = []
        
        for n, coin in enumerate(coins):
            puzzle_hash = coin.puzzle_hash
            #print(n);
            #print(coin);
            #print('----------------------')
            #secret_key = self.puzzle_hash_to_private_key[puzzle_hash]['private_key']
            print(self.puzzle_hash_to_private_key[puzzle_hash])
            public_key = hexstr_to_bytes(self.puzzle_hash_to_private_key[puzzle_hash]['public_key'])
            puzzle = puzzle_for_pk(public_key)
            if n == 0:
                message_list = [c.name() for c in coins]
                for outputs in condition_dic[ConditionOpcode.CREATE_COIN]:
                    message_list.append(Coin(coin.name(), outputs.vars[0], int_from_bytes(outputs.vars[1])).name())
                message = std_hash(b"".join(message_list))
                condition_dic[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT].append(
                    ConditionWithArgs(ConditionOpcode.CREATE_COIN_ANNOUNCEMENT, [message])
                )
                primary_announcement_hash = Announcement(coin.name(), message).name()
                secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT].append(
                    ConditionWithArgs(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT, [primary_announcement_hash])
                )
                main_solution = self.make_solution(condition_dic)
                spends.append(CoinSpend(coin, puzzle, main_solution))
            else:
                spends.append(CoinSpend(coin, puzzle, self.make_solution(secondary_coins_cond_dic)))
        return spends

    def sign_transaction(self, coin_spends: List[CoinSpend]) -> SpendBundle:
        signatures = []
        solution: Program
        puzzle: Program
        for coin_spend in coin_spends:  # type: ignore # noqa
            #secret_key = self.get_private_key_for_puzzle_hash(coin_spend.coin.puzzle_hash)
            secret_key = self.puzzle_hash_to_private_key[coin_spend.coin.puzzle_hash]['private_key']
            print("-----------------")
            print(secret_key)
            print("-----------------")
            PrivateKeyText = PrivateKey.from_bytes(hexstr_to_bytes(secret_key))
            print(PrivateKeyText)
            print("-----------------")
            synthetic_secret_key = calculate_synthetic_secret_key(PrivateKeyText, DEFAULT_HIDDEN_PUZZLE_HASH)
            err, con, cost = conditions_for_solution(
                coin_spend.puzzle_reveal, coin_spend.solution, self.constants.MAX_BLOCK_COST_CLVM
            )
            if not con:
                raise ValueError(err)
            conditions_dict = conditions_by_opcode(con)

            for _, msg in pkm_pairs_for_conditions_dict(
                conditions_dict, bytes(coin_spend.coin.name()), self.constants.AGG_SIG_ME_ADDITIONAL_DATA
            ):
                signature = AugSchemeMPL.sign(synthetic_secret_key, msg)
                signatures.append(signature)
        aggsig = AugSchemeMPL.aggregate(signatures)
        spend_bundle = SpendBundle(coin_spends, aggsig)
        return spend_bundle

    def generate_signed_transaction(
        self,
        amount: uint64,
        to_puzzle_hash: bytes32,
        change_puzzle_hash: bytes32,
        coin: Coin,
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = None,
        fee: int = 0,
    ) -> SpendBundle:
        if condition_dic is None:
            condition_dic = {}
        transaction = self.generate_unsigned_transaction(amount, to_puzzle_hash, change_puzzle_hash, [coin], condition_dic, fee)
        assert transaction is not None
        return self.sign_transaction(transaction)

    def generate_signed_transaction_multiple_coins(
        self,
        amount: uint64,
        to_puzzle_hash: bytes32,
        amount_swap: uint64,
        to_puzzle_hash_swap: bytes32,
        change_puzzle_hash: bytes32,
        change_number: uint64,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = None,
        fee: int = 0,
    ) -> SpendBundle:
        if condition_dic is None:
            condition_dic = {}
        transaction = self.generate_unsigned_transaction(amount, to_puzzle_hash, amount_swap, to_puzzle_hash_swap, change_puzzle_hash, change_number, coins, condition_dic, fee)
        assert transaction is not None
        return self.sign_transaction(transaction)



if __name__ == "__main__":
    wt=WalletTool(DEFAULT_CONSTANTS)
    asyncio.run(wt.push_transaction())
    
