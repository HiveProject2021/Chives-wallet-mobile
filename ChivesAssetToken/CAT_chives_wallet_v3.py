import json
import time
import asyncio
import aiosqlite
import sqlite3
import logging
import redis
import base64


from typing import Any, Dict, List, Optional, Set, Tuple

from blspy import AugSchemeMPL, G2Element, PrivateKey

from chives.consensus.constants import ConsensusConstants
from chives.util.hash import std_hash
from chives.types.announcement import Announcement
from chives.types.blockchain_format.coin import Coin
from chives.types.blockchain_format.program import Program
from chives.types.blockchain_format.sized_bytes import bytes32
from chives.types.coin_spend import CoinSpend
from chives.types.condition_opcodes import ConditionOpcode
from chives.types.condition_with_args import ConditionWithArgs
from chives.types.spend_bundle import SpendBundle
from chives.util.clvm import int_from_bytes, int_to_bytes
from chives.util.condition_tools import conditions_by_opcode, conditions_for_solution, pkm_pairs_for_conditions_dict
from chives.util.ints import uint32, uint64
from chives.util.byte_types import hexstr_to_bytes
from chives.util.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict


from chives.types.blockchain_format.classgroup import ClassgroupElement
from chives.types.blockchain_format.coin import Coin
from chives.types.blockchain_format.foliage import TransactionsInfo
from chives.types.blockchain_format.program import SerializedProgram
from chives.types.blockchain_format.sized_bytes import bytes32
from chives.types.blockchain_format.slots import InfusedChallengeChainSubSlot
from chives.types.blockchain_format.vdf import VDFInfo, VDFProof
from chives.types.end_of_slot_bundle import EndOfSubSlotBundle
from chives.types.full_block import FullBlock
from chives.types.unfinished_block import UnfinishedBlock

from chives.wallet.derive_keys import master_sk_to_wallet_sk,master_sk_to_wallet_sk_unhardened
from chives.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
    solution_for_conditions,
)
from chives.wallet.puzzles.puzzle_utils import (
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
from chives.util.keychain import Keychain, bytes_from_mnemonic, bytes_to_mnemonic, generate_mnemonic, mnemonic_to_seed

from chives.consensus.default_constants import DEFAULT_CONSTANTS

from chives.rpc.full_node_rpc_api import FullNodeRpcApi
from chives.rpc.full_node_rpc_client import FullNodeRpcClient
from chives.util.default_root import DEFAULT_ROOT_PATH
from chives.util.config import load_config
from chives.util.ints import uint16
from chives.util.misc import format_bytes

from chives.wallet.transaction_record import TransactionRecord

from chives.wallet.cc_wallet.cat_constants import DEFAULT_CATS
from chives.wallet.cc_wallet.cc_info import CCInfo
from chives.wallet.cc_wallet.cc_utils import (
    CC_MOD,
    SpendableCC,
    construct_cc_puzzle,
    unsigned_spend_bundle_for_spendable_ccs,
    match_cat_puzzle,
)

from chives.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
    solution_for_conditions,
)
import dataclasses
from dataclasses import replace
from dataclasses import dataclass

from chives.wallet.derivation_record import DerivationRecord
from chives.wallet.lineage_proof import LineageProof
from chives.wallet.puzzles.genesis_checkers import ALL_LIMITATIONS_PROGRAMS
from chives.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
)
from chives.wallet.transaction_record import TransactionRecord
from chives.wallet.util.transaction_type import TransactionType
from chives.wallet.util.wallet_types import WalletType
from chives.wallet.wallet import Wallet
from chives.wallet.wallet_coin_record import WalletCoinRecord
from chives.wallet.wallet_info import WalletInfo
from chives.util.streamable import Streamable, streamable
from chives.util.bech32m import decode_puzzle_hash, encode_puzzle_hash


# This should probably not live in this file but it's for experimental right now
@dataclasses.dataclass
class Payment:
    puzzle_hash: bytes32
    amount: uint64
    memos: Optional[List[Optional[bytes]]] = None
    
@dataclass(frozen=True)
@streamable
class CCInfo(Streamable):
    limitations_program_hash: bytes32
    my_genesis_checker: Optional[Program]  # this is the program
    lineage_proofs: List[Tuple[bytes32, Optional[LineageProof]]]  # {coin.name(): lineage_proof}


class WalletTool:
    next_address = 0
    pubkey_num_lookup: Dict[bytes, uint32] = {}

    def __init__(self, constants: ConsensusConstants, sk: Optional[PrivateKey] = None):
        
        
        empty_bytes = bytearray(32)
        self.cc_info = CCInfo(empty_bytes, None, [])
        info_as_string = bytes(self.cc_info).hex()
        
        self.constants = constants
        self.current_balance = 0
        self.my_utxos: set = set()
        self.generator_lookups: Dict = {}
        self.puzzle_pk_cache: Dict = {}
        self.CAT_ASSET_ID = ""
        self.inner_puzzle_for_cc_puzhash = {}
        self.get_new_inner_hash = ""
        self.LINEAGE_PROOF_NAME_TO_DICT = {}
        self.get_keys = {}
        #print(constants)
        #print()
        #print()
        #print()
     
    async def  push_transaction(self):           
        #mnemonic = generate_mnemonic()
        #when you want to make a send transaction, you must need a account.
        #here it is to fill the mnemonic works and to make a account
        
        # Tail hash, aka the CAT asset id
        # tail_hash = bytes32.fromhex('3e3a7614a02d9714a21927ef99c7ef9bf8270e374dc6ecc48f2619cbc70c4ddc')
        
        #连接REDIS        
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        
        CHIVES_WALLET_CLI_LOCKING = r.hget("CHIVES_WALLET_CLI_LOCKING","CAT_chives_wallet_v3.py")
        if CHIVES_WALLET_CLI_LOCKING is None:
            CHIVES_WALLET_CLI_LOCKING = 0
        CHIVES_WALLET_CLI_LOCKING = int(CHIVES_WALLET_CLI_LOCKING)
        #上一个任务没有执行完成,请等待
        要求等待时间 = 300
        #CHIVES_WALLET_CLI_LOCKING = 0
        if int(time.time()) - CHIVES_WALLET_CLI_LOCKING < 要求等待时间 :
            print("上一个任务没有执行完成,请等待秒数:")
            print(要求等待时间 - int(time.time()) + CHIVES_WALLET_CLI_LOCKING)
            return
        #开始执行,标记为当前时间
        if CHIVES_WALLET_CLI_LOCKING == 0:            
            r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_chives_wallet_v3.py", int(time.time()) )    
        
        if ( int(time.time()) - CHIVES_WALLET_CLI_LOCKING ) > 要求等待时间:
            #执行时间超过15分钟,已经超时,可以再次执行
            r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_chives_wallet_v3.py", int(time.time()) )
        
        print(f"CHIVES_WALLET_CLI_LOCKING: {CHIVES_WALLET_CLI_LOCKING}")
        
        
        #连接主节点
        config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
        self_hostname = config["self_hostname"]
        rpc_port = config["full_node"]["rpc_port"]
        client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
        
        #连接数据库
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("/home/ubuntu/.chives/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
        
        
        #得到需要发送的任务清单,每次发送支持发送多个地址
        CHIVES_WALLET_TX_DOING_CHIVES = r.hgetall("CHIVES_WALLET_TX_DOING_ASSET_TOKEN_CHIVES")
        #print(CHIVES_WALLET_TX_DOING_CHIVES)
        for ORDER_KEY,ORDER_KEY_STATUS in CHIVES_WALLET_TX_DOING_CHIVES.items():
            if ORDER_KEY_STATUS == bytes("READY","ascii"):
                print('===================')
                print(ORDER_KEY)
                TODO_ORDER = r.hget("CHIVES_WALLET_TX_ASSET_TOKEN_CHIVES",ORDER_KEY)
                #print('===================')
                #print(TODO_ORDER)
                TODO_ORDER_64 = base64.b64decode(TODO_ORDER)
                #print('===================')
                #print(TODO_ORDER_64)
                #print('===================')
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
                    #TODO_ORDER = r.hset("CHIVES_WALLET_TX_DOING_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                    #TODO_ORDER = r.hset("CHIVES_WALLET_TX_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_64_TEXT)
                else:
                    #开始处理发送TOKEN的工作
                    self.CAT_ASSET_ID = TODO_ORDER_JSON['ASSET_ID']
                    self.limitations_program_hash = hexstr_to_bytes(self.CAT_ASSET_ID)
                    self.get_new_inner_hash = TODO_ORDER_JSON['CHANGE_PUZZLEHASH']
                    #print(type(self.get_new_inner_hash))

                    #mnemonic = ""
                    #mnemonic = TODO_ORDER_JSON['ASSET_ID']
                    #entropy = bytes_from_mnemonic(mnemonic)
                    #seed = mnemonic_to_seed(mnemonic, "")
                    #self.private_key = AugSchemeMPL.key_gen(seed)
                    #fingerprint = self.private_key.get_g1().get_fingerprint()
                    
                    fee = uint64(0)
                    #生成要发送的金额和地址以及备注等数组
                    SendToAmountAll = 0
                    ADDRESS_NUMBER = 0
                    SEND_ADDRESS_KEY_CACHE = []
                    SendToAmountArray = []
                    SendToPuzzleHashArray = []
                    SendToMemosArray = []
                    for TO_USER in TODO_ORDER_JSON['TO_USER_LIST']:
                        # print(TO_USER)
                        SendToAmountArray.append(int(float(TO_USER['AMOUNT'])))
                        SendToPuzzleHashArray.append(hexstr_to_bytes(TO_USER['PUZZLE_HASH']))
                        SendToMemosArray.append("")
                        SendToAmountAll += int(float(TO_USER['AMOUNT']))
                        
                    #print(SendToAmountArray)
                    #print(SendToPuzzleHashArray)
                    #print(SendToMemosArray)
                    #return;
                    
                    #得到指定账户的300个地址.
                    AllPuzzleHashArray = []
                    i = 0
                    coinList = []
                    CurrentCoinAmount = 0
                    LINEAGE_PROOF_PARENT_PH = []
                    CHIVES_CAT_COIN_NAME_IS_USED_ARRAY = []
                    for SUB_KEY_ARRAY in TODO_ORDER_JSON['WALLET_DETAIL']:
                        private = SUB_KEY_ARRAY['private_key']
                        private = PrivateKey.from_bytes(hexstr_to_bytes(private))
                        public_key = hexstr_to_bytes(SUB_KEY_ARRAY['public_key'])
                        puzzlehash = SUB_KEY_ARRAY['puzzle_hash']
                        address = SUB_KEY_ARRAY['address']
                        CAT_puzzlehash = SUB_KEY_ARRAY['CAT_puzzlehash']
                        CAT_address = SUB_KEY_ARRAY['CAT_address']
                        coin_parent = SUB_KEY_ARRAY['coin_parent']
                        amount = SUB_KEY_ARRAY['amount']
                        inner_puzzle = puzzle_for_pk(public_key)
                        #limitations_program_hash = hexstr_to_bytes(self.CAT_ASSET_ID)
                        #cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash, inner_puzzle)
                        #cc_puzzle_hash = cc_puzzle.get_tree_hash()
                        #print(CAT_puzzlehash)
                        #print(cc_puzzle_hash)
                        AllPuzzleHashArray.append(str(CAT_puzzlehash))
                        #把CAT_PH转换为INNER_PH
                        self.inner_puzzle_for_cc_puzhash[str(CAT_puzzlehash)] = inner_puzzle
                        #缓存公钥和私钥
                        self.get_keys[puzzlehash] = {'pubkey':public_key,'private':private}
                        #i = i + 1
                        #if i > 100:
                        #    break;
                        
                        #构建输入的COIN LIST 
                        coin = Coin(hexstr_to_bytes(coin_parent), hexstr_to_bytes(CAT_puzzlehash), uint64(amount))
                        #查询该COIN是否被花费
                        if r.hget("CHIVES_CAT_COIN_NAME_IS_USED",str(coin.name())) is None:
                            CurrentCoinAmount += uint64(amount)
                            coinList.append(coin)
                            #需要缓存每一个币的父币值,去查询他们的父币信息 下一个SQL中去COIN_NAME过滤
                            LINEAGE_PROOF_PARENT_PH.append(coin_parent)
                            #标记该COIN已经被花费过,不能再次使用
                            CHIVES_CAT_COIN_NAME_IS_USED_ARRAY.append(str(coin.name()))
                            if(CurrentCoinAmount>SendToAmountAll):
                                break
                    
                    #print("self.get_new_inner_hash===============================")
                    #print(self.get_new_inner_hash)
                    #print("AllPuzzleHashArray===============================")
                    #print(AllPuzzleHashArray)
                    #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
                    separator = "','"
                    AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
                    AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
                    
                    #SendToAmountAll = uint64(1)
                    #SendToPuzzleHash = hexstr_to_bytes("61d1f3efb8e1e0c3e8e21f19714cc22c5b1b17099f059dae19f05db922706e43")
                    #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
                    
                    #查询未花费记录
                    #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
                    '''
                    cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
                    rows = await cursor.fetchall()
                    coinList = []
                    CurrentCoinAmount = 0
                    LINEAGE_PROOF_PARENT_PH = []
                    CHIVES_CAT_COIN_NAME_IS_USED_ARRAY = []
                    for row in rows:
                        coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
                        #查询该COIN是否被花费
                        if r.hget("CHIVES_CAT_COIN_NAME_IS_USED",str(coin.name())) is None:
                            CurrentCoinAmount += uint64.from_bytes(row[7])
                            coinList.append(coin)
                            #需要缓存每一个币的父币值,去查询他们的父币信息 下一个SQL中去COIN_NAME过滤
                            LINEAGE_PROOF_PARENT_PH.append(row[6])
                            #print(row) 
                            #标记该COIN已经被花费过,不能再次使用
                            CHIVES_CAT_COIN_NAME_IS_USED_ARRAY.append(str(coin.name()))
                            if(CurrentCoinAmount>SendToAmountAll):
                                break
                    '''
                    #判断是否余额不足
                    if CurrentCoinAmount<SendToAmountAll:
                        #更新发送记录的主体内容 
                        TODO_ORDER_JSON['TX_STATUS'] 			= "FAIL";
                        TODO_ORDER_JSON['TX_RESULT'] 			= "Insufficient balance";
                        TODO_ORDER_JSON['TX_ID'] 			    = f"Insufficient balance. Balance: {CurrentCoinAmount} Want send: {SendToAmountAll}";
                        TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                        TODO_ORDER_JSON['TX_PATH'] 			    = "CAT_chives_wallet_v3.py";
                        TODO_ORDER_JSON['WALLET_DETAIL'] 		= {};
                        #把执行以后的状态写入REDIS
                        TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                        TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                        #print(TODO_ORDER_JSON_TEXT)
                        #print(TODO_ORDER_64_TEXT)
                        r.hset("CHIVES_WALLET_TX_DOING_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                        r.hset("CHIVES_WALLET_TX_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_64_TEXT)                        
                        print (f"Insufficient balance. Balance: {CurrentCoinAmount} Want send: {SendToAmountAll}")
                        continue
                        
                    #print("rows===============================")
                    #print(rows)
                    print("coinList===============================")
                    print(coinList)
                    print("LINEAGE_PROOF_PARENT_PH===============================")
                    print(LINEAGE_PROOF_PARENT_PH)
                    print("===============================")
                    
                    #再次在数据库里面查询,到到LINEAGE_PROOF的COIN的值.父币一定是花费过的币
                    #lineage_proof----------------------------{'amount': 4340297000, 'inner_puzzle_hash': '0x71ecf37741c95bca22c90325a19a72e39320bae97486138a9245531332a64ebe', 'parent_name': '0x122db8ce1ae4b4dc6d5d5100ddb64f6b80f5962b01efdf0dcad5a2cbb9921cbc'}
                    separator = "','"
                    AllPuzzleHashArrayText = separator.join(LINEAGE_PROOF_PARENT_PH)
                    AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
                    cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=1 and coin_name in ("+AllPuzzleHashArrayText+")")
                    rows = await cursor.fetchall()
                    self.LINEAGE_PROOF_NAME_TO_DICT = {}
                    #print("self.inner_puzzle_for_cc_puzhash=========================")
                    #print(self.inner_puzzle_for_cc_puzhash)
                    for row in rows:
                        coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
                        LINEAGE_SINGLE = {}
                        LINEAGE_SINGLE['amount'] = uint64.from_bytes(row[7])
                        temp_cat_puzzle_hash = row[5]
                        if temp_cat_puzzle_hash not in self.inner_puzzle_for_cc_puzhash.keys():
                            #父币是其它人给我们发送过来的,不是属于我们自己,所以需要一个单独的写法来获得inner_puzzle
                            print(row)
                            get_puzzle_and_solution = await client_node.get_puzzle_and_solution(coin.name(), height=int(row[2]))
                            matched, curried_args = match_cat_puzzle(get_puzzle_and_solution.puzzle_reveal)
                            if matched:        
                                mod_hash, genesis_coin_checker_hash, inner_puzzle = curried_args
                                ASSET_ID = str(genesis_coin_checker_hash)[2:]
                                inner_puzzle_hash = inner_puzzle.get_tree_hash()
                                print(f"ASSET_ID: {ASSET_ID}")
                                print(f"coin.name(): {coin.name()}")
                                print(f"inner_puzzle_hash: {inner_puzzle_hash}")
                                print(f"cat_puzzle_hash: {row[5]}")
                                LINEAGE_SINGLE['inner_puzzle_hash'] = inner_puzzle_hash
                            else:   
                                raise ValueError(f"coin.name(): {coin.name()} not get the inner_puzzle")
                        else:
                            LINEAGE_SINGLE['inner_puzzle_hash'] = self.inner_puzzle_for_cc_puzhash[temp_cat_puzzle_hash].get_tree_hash()
                        LINEAGE_SINGLE['parent_name'] = row[6]
                        self.LINEAGE_PROOF_NAME_TO_DICT[str(row[0])] = LineageProof(hexstr_to_bytes(LINEAGE_SINGLE['parent_name']), LINEAGE_SINGLE['inner_puzzle_hash'], LINEAGE_SINGLE['amount'])
                    print("LINEAGE_PROOF_NAME_TO_DICT===============================")
                    print(self.LINEAGE_PROOF_NAME_TO_DICT)  
                    await cursor.close()
                    
                    
                    if len(coinList)==0:
                        print("ERROR TRIP===============================")
                        print("Not select any one coin to send")
                        return 
                        
                    #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
                    generate_signed_transaction = await self.generate_signed_transaction(
                        SendToAmountArray,
                        SendToPuzzleHashArray,
                        fee,
                        coinList,
                        memos=SendToMemosArray,
                    )
                    #print(generate_signed_transaction)
                    
                    #提交交易记录到区块链网络
                    push_tx = {}
                    try:
                        push_tx = await client_node.push_tx(generate_signed_transaction)
                        print("push_tx=====================================================")
                        print(push_tx)
                        #{'status': 'SUCCESS', 'success': True}
                        if push_tx['status']=="SUCCESS" and push_tx['success']==True:
                            #更新发送记录的主体内容
                            TODO_ORDER_JSON['TX_STATUS'] 			= "DONE";
                            TODO_ORDER_JSON['TX_RESULT'] 			= push_tx['status'];
                            TODO_ORDER_JSON['TX_ID'] 			    = str(generate_signed_transaction.name());
                            TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                            TODO_ORDER_JSON['TX_PATH'] 			    = "CAT_chives_wallet_v3.py";
                            TODO_ORDER_JSON['WALLET_DETAIL'] 		= {};
                            #把执行以后的状态写入REDIS
                            TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                            TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                            #print(TODO_ORDER_JSON_TEXT)
                            #print(TODO_ORDER_64_TEXT)
                            r.hset("CHIVES_WALLET_TX_DOING_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                            r.hset("CHIVES_WALLET_TX_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_64_TEXT)
                            
                            #作废已经花费过的COIN
                            for CHIVES_CAT_COIN_NAME_IS_USED_KEY in CHIVES_CAT_COIN_NAME_IS_USED_ARRAY:
                                r.hset("CHIVES_CAT_COIN_NAME_IS_USED",CHIVES_CAT_COIN_NAME_IS_USED_KEY,1)
                        #print(type(push_tx))
                    except Exception as e:
                        if "DOUBLE_SPEND" in str(e):
                            print("DOUBLE_SPEND push_tx=====================================================")
                            #更新发送记录的主体内容
                            TODO_ORDER_JSON['TX_STATUS'] 			= "DOUBLE_SPEND";
                            TODO_ORDER_JSON['TX_RESULT'] 			= "DOUBLE_SPEND";
                            TODO_ORDER_JSON['TX_ID'] 			    = str(generate_signed_transaction.name());
                            TODO_ORDER_JSON['TX_TIME'] 			    = int(time.time());
                            TODO_ORDER_JSON['TX_PATH'] 			    = "CAT_chives_wallet_v3.py";
                            TODO_ORDER_JSON['WALLET_DETAIL'] 		= {};
                            #把执行以后的状态写入REDIS
                            TODO_ORDER_JSON_TEXT = json.dumps(TODO_ORDER_JSON)
                            TODO_ORDER_64_TEXT = base64.b64encode(TODO_ORDER_JSON_TEXT.encode('ascii'))
                            #print(TODO_ORDER_JSON_TEXT)
                            #print(TODO_ORDER_64_TEXT)
                            r.hset("CHIVES_WALLET_TX_DOING_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_JSON['TX_STATUS'])
                            r.hset("CHIVES_WALLET_TX_ASSET_TOKEN_CHIVES",ORDER_KEY,TODO_ORDER_64_TEXT)
                        else:
                            print("未捕捉错误 push_tx=====================================================")
                            print(e)
                    finally:
                        print("finally=====================================================")
                    
            else:
                print(f"ORDER_KEY_STATUS IS {ORDER_KEY_STATUS}")
        
        #把时间设置为0,取消LOCK
        r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_chives_wallet_v3.py", 0 )        
        #关闭数据库
        await db_connection.close()
        #关闭结点连接
        client_node.close()
        await client_node.await_closed()

    async def generate_signed_transaction(
        self,
        amounts: List[uint64],
        puzzle_hashes: List[bytes32],
        fee: uint64 = uint64(0),
        coins: Set[Coin] = None,
        memos: Optional[List[List[bytes]]] = None,
    ) -> List[SpendBundle]:
        if memos is None:
            memos = [[] for _ in range(len(puzzle_hashes))]

        if not (len(memos) == len(puzzle_hashes) == len(amounts)):
            raise ValueError("Memos, puzzle_hashes, and amounts must have the same length")

        payments = []
        for amount, puzhash, memo_list in zip(amounts, puzzle_hashes, memos):
            memos_with_hint = [puzhash]
            memos_with_hint.extend(memo_list)
            payments.append(Payment(puzhash, amount, memos_with_hint))

        unsigned_spend_bundle, chives_tx = await self.generate_unsigned_spendbundle(payments, fee, coins=coins)
        spend_bundle = await self.sign(unsigned_spend_bundle)

        return spend_bundle
    
    async def generate_unsigned_spendbundle(
        self,
        payments: List[Payment],
        fee: uint64 = uint64(0),
        cat_discrepancy: Optional[Tuple[int, Program]] = None,  # (extra_delta, limitations_solution)
        coins: Set[Coin] = None,
    ) -> Tuple[SpendBundle, Optional[TransactionRecord]]:
        if cat_discrepancy is not None:
            extra_delta, limitations_solution = cat_discrepancy
        else:
            extra_delta, limitations_solution = 0, Program.to([])
        payment_amount: int = sum([p.amount for p in payments])
        starting_amount: int = payment_amount - extra_delta

        if coins is None:
            cat_coins = await self.select_coins(uint64(starting_amount))
        else:
            cat_coins = coins

        selected_cat_amount = sum([c.amount for c in cat_coins])
        
        if selected_cat_amount < starting_amount :
            raise ValueError(f"Insufficient balance. Balance: {selected_cat_amount} Want send: {starting_amount}")

        # Figure out if we need to absorb/melt some XCH as part of this
        regular_chives_to_claim: int = 0
        if payment_amount > starting_amount:
            fee = uint64(fee + payment_amount - starting_amount)
        elif payment_amount < starting_amount:
            regular_chives_to_claim = payment_amount

        #need_chives_transaction = (fee > 0 or regular_chives_to_claim > 0) and (fee - regular_chives_to_claim != 0)
        need_chives_transaction = False
        # Calculate standard puzzle solutions
        change = selected_cat_amount - starting_amount
        primaries = []
        for payment in payments:
            primaries.append({"puzzlehash": payment.puzzle_hash, "amount": payment.amount, "memos": payment.memos})

        if change > 0:
            changepuzzlehash = hexstr_to_bytes(self.get_new_inner_hash)
            primaries.append({"puzzlehash": changepuzzlehash, "amount": change})

        limitations_program_reveal = Program.to([])
        if self.cc_info.my_genesis_checker is None:
            assert cat_discrepancy is None
        elif cat_discrepancy is not None:
            limitations_program_reveal = self.cc_info.my_genesis_checker

        # Loop through the coins we've selected and gather the information we need to spend them
        spendable_cc_list = []
        chives_tx = None
        first = True
        for coin in cat_coins:
            if first:
                first = False
                '''
                if need_chives_transaction:
                    if fee > regular_chives_to_claim:
                        announcement = Announcement(coin.name(), b"$", b"\xca")
                        chives_tx, _ = await self.create_tandem_xch_tx(
                            fee, uint64(regular_chives_to_claim), announcement_to_assert=announcement
                        )
                        innersol = self.standard_wallet.make_solution(
                            primaries=primaries, coin_announcements={announcement.message}
                        )
                    elif regular_chives_to_claim > fee:
                        chives_tx, _ = await self.create_tandem_xch_tx(fee, uint64(regular_chives_to_claim))
                        innersol = self.standard_wallet.make_solution(
                            primaries=primaries, coin_announcements_to_assert={announcement.name()}
                        )
                else:
                    innersol = self.standard_wallet.make_solution(primaries=primaries)
                '''
                #print(primaries)
                innersol = self.make_solution(primaries=primaries)
            else:
                innersol = self.make_solution()
            inner_puzzle = self.inner_puzzle_for_cc_puzhash[str(coin.puzzle_hash)]
            lineage_proof = self.LINEAGE_PROOF_NAME_TO_DICT[str(coin.parent_coin_info)]
            assert lineage_proof is not None
            print("coin===============================")
            print(coin)
            print("self.limitations_program_hash===============================")
            print(self.limitations_program_hash)
            print("inner_puzzle===============================")
            print(inner_puzzle)
            #print("innersol===============================")
            #print(innersol)
            print("limitations_solution===============================")
            print(limitations_solution)
            print("extra_delta===============================")
            print(extra_delta)
            print("lineage_proof===============================")
            print(lineage_proof)
            print("limitations_program_reveal===============================")
            print(limitations_program_reveal)
            print("开始处理 SpendableCC......................................")
            
            new_spendable_cc = SpendableCC(
                coin,
                self.limitations_program_hash,
                inner_puzzle,
                innersol,
                limitations_solution=limitations_solution,
                extra_delta=extra_delta,
                lineage_proof=lineage_proof,
                limitations_program_reveal=limitations_program_reveal,
            )
            spendable_cc_list.append(new_spendable_cc)

        cat_spend_bundle = unsigned_spend_bundle_for_spendable_ccs(CC_MOD, spendable_cc_list)
        chives_spend_bundle = SpendBundle([], G2Element())
        if chives_tx is not None and chives_tx.spend_bundle is not None:
            chives_spend_bundle = chives_tx.spend_bundle

        return (
            SpendBundle.aggregate(
                [
                    cat_spend_bundle,
                    chives_spend_bundle,
                ]
            ),
            chives_tx,
        )
    
    def make_solution(
        self,
        primaries: Optional[List[Dict[str, Any]]] = None,
        min_time=0,
        me=None,
        coin_announcements: Optional[Set[bytes32]] = None,
        coin_announcements_to_assert: Optional[Set[bytes32]] = None,
        puzzle_announcements: Optional[Set[bytes32]] = None,
        puzzle_announcements_to_assert: Optional[Set[bytes32]] = None,
        fee=0,
    ) -> Program:
        assert fee >= 0
        condition_list = []
        if primaries:
            for primary in primaries:
                if "memos" in primary:
                    memos = primary["memos"]
                else:
                    memos = None
                condition_list.append(make_create_coin_condition(primary["puzzlehash"], primary["amount"], memos))
        if min_time > 0:
            condition_list.append(make_assert_absolute_seconds_exceeds_condition(min_time))
        if me:
            condition_list.append(make_assert_my_coin_id_condition(me["id"]))
        if fee:
            condition_list.append(make_reserve_fee_condition(fee))
        if coin_announcements:
            for announcement in coin_announcements:
                condition_list.append(make_create_coin_announcement(announcement))
        if coin_announcements_to_assert:
            for announcement_hash in coin_announcements_to_assert:
                condition_list.append(make_assert_coin_announcement(announcement_hash))
        if puzzle_announcements:
            for announcement in puzzle_announcements:
                condition_list.append(make_create_puzzle_announcement(announcement))
        if puzzle_announcements_to_assert:
            for announcement_hash in puzzle_announcements_to_assert:
                condition_list.append(make_assert_puzzle_announcement(announcement_hash))
        return solution_for_conditions(condition_list)
    
    async def sign(self, spend_bundle: SpendBundle) -> SpendBundle:
        sigs: List[G2Element] = []
        for spend in spend_bundle.coin_spends:
            matched, puzzle_args = match_cat_puzzle(spend.puzzle_reveal.to_program())
            if matched:
                _, _, inner_puzzle = puzzle_args
                puzzle_hash = inner_puzzle.get_tree_hash()
                pubkey = self.get_keys[str(puzzle_hash)]['pubkey']
                private = self.get_keys[str(puzzle_hash)]['private']
                #print(self.get_keys)
                #print(private)
                #print(DEFAULT_HIDDEN_PUZZLE_HASH)
                synthetic_secret_key = calculate_synthetic_secret_key(private, DEFAULT_HIDDEN_PUZZLE_HASH)
                error, conditions, cost = conditions_dict_for_solution(
                    spend.puzzle_reveal.to_program(),
                    spend.solution.to_program(),
                    self.constants.MAX_BLOCK_COST_CLVM,
                )
                if conditions is not None:
                    synthetic_pk = synthetic_secret_key.get_g1()
                    for pk, msg in pkm_pairs_for_conditions_dict(
                        conditions, spend.coin.name(), self.constants.AGG_SIG_ME_ADDITIONAL_DATA
                    ):
                        try:
                            assert synthetic_pk == pk
                            sigs.append(AugSchemeMPL.sign(synthetic_secret_key, msg))
                        except AssertionError:
                            raise ValueError("This spend bundle cannot be signed by the CAT wallet")

        agg_sig = AugSchemeMPL.aggregate(sigs)
        return SpendBundle.aggregate([spend_bundle, SpendBundle([], agg_sig)])


    # ##########################################################################################    
    async def push_tx_NOT_USED(self,generate_signed_transaction):
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx(generate_signed_transaction)
            return push_res
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
        
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
                    print('===================')
                    return master_sk_to_wallet_sk(self.private_key, uint32(child))
        raise ValueError(f"Do not have the keys for puzzle hash {puzzle_hash}")

if __name__ == "__main__":
    wt=WalletTool(DEFAULT_CONSTANTS)
    asyncio.run(wt.push_transaction())
    
