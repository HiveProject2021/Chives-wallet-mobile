import json
import time
import asyncio
import aiosqlite
import sqlite3
import logging
import redis


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


class WalletToolCat:
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
        self.inner_puzzle_for_cc_puzhash = {}
        self.get_new_inner_hash = ""
        self.LINEAGE_PROOF_NAME_TO_DICT = {}
        self.get_keys = {}
        self.CHIVES_COIN_NAME_IS_USED_ARRAY = {}
        #print(constants)
        #print()
        #print()
        #print()
     
    async def  push_transaction_cat(self):           
        #mnemonic = generate_mnemonic()
        #when you want to make a send transaction, you must need a account.
        #here it is to fill the mnemonic works and to make a account
        
        # Tail hash, aka the CAT asset id
        # tail_hash = bytes32.fromhex('3e3a7614a02d9714a21927ef99c7ef9bf8270e374dc6ecc48f2619cbc70c4ddc')
           
        CAT_ASSET_ID                    = "3e3a7614a02d9714a21927ef99c7ef9bf8270e374dc6ecc48f2619cbc70c4ddc"
        self.limitations_program_hash   = hexstr_to_bytes(CAT_ASSET_ID)
        # 第二个KITTY账户 
        #mnemonic = ""
        mnemonic = ""
        entropy = bytes_from_mnemonic(mnemonic)
        seed = mnemonic_to_seed(mnemonic, "")
        self.private_key = AugSchemeMPL.key_gen(seed)
        fingerprint = self.private_key.get_g1().get_fingerprint()
        
        #得到指定账户的300个地址.
        AllPuzzleHashArray = []
        for i in range(0, 5):
            private = master_sk_to_wallet_sk(self.private_key, i)
            pubkey = private.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            puzzle_hash = str(puzzle.get_tree_hash())
            #AllPuzzleHashArray.append(puzzle_hash);
            
            limitations_program_hash = hexstr_to_bytes(CAT_ASSET_ID)
            inner_puzzle = puzzle_for_pk(bytes(pubkey))
            cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash, inner_puzzle)
            cc_puzzle_hash = cc_puzzle.get_tree_hash()
            AllPuzzleHashArray.append(str(cc_puzzle_hash))
            #把CAT_PH转换为INNER_PH
            self.inner_puzzle_for_cc_puzhash[str(cc_puzzle_hash)] = inner_puzzle
            #缓存找零地址
            if i==0:
                self.get_new_inner_hash = puzzle_hash
                self.get_new_cc_puzzle_hash = str(cc_puzzle_hash)
            #缓存公钥和私钥
            self.get_keys[puzzle_hash] = {'pubkey':pubkey,'private':private}           
        
        for i in range(0, 5):
            private = master_sk_to_wallet_sk_unhardened(self.private_key, i)
            pubkey = private.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))            
            puzzle_hash = str(puzzle.get_tree_hash())
            #AllPuzzleHashArray.append(puzzle_hash);
            
            limitations_program_hash = hexstr_to_bytes(CAT_ASSET_ID)
            inner_puzzle = puzzle_for_pk(bytes(pubkey))
            cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash, inner_puzzle)
            cc_puzzle_hash = cc_puzzle.get_tree_hash()
            AllPuzzleHashArray.append(str(cc_puzzle_hash))
            #把CAT_PH转换为INNER_PH
            self.inner_puzzle_for_cc_puzhash[str(cc_puzzle_hash)] = inner_puzzle
            if i==0:
                self.get_new_inner_hash = puzzle_hash
                self.get_new_cc_puzzle_hash = str(cc_puzzle_hash)
            #缓存公钥和私钥
            self.get_keys[puzzle_hash] = {'pubkey':pubkey,'private':private}
            
        #print("self.get_new_inner_hash===============================")
        #print(self.get_new_inner_hash)
        #print("AllPuzzleHashArray===============================")
        #print(AllPuzzleHashArray)
        #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
        separator = "','"
        AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
        AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
        
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
        db_connection = await aiosqlite.connect("/home/wang/.chives/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
        
        #手工输入来构建参数部分代码 根据REDIS的值,一次性发送多个地址.        
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        CHIVES_KITTY_HAS_ACCOUNT_PET_20211230 = r.hgetall("CHIVES_KITTY_HAS_ACCOUNT_PET_20211230")
        ADDRESS_NUMBER = 0
        SEND_ADDRESS_KEY_CACHE = []
        SendToAmountArray = []
        SendToPuzzleHashArray = []
        SendToMemosArray = []
        for SEND_ADDRESS_KEY,SEND_ADDRESS_VALUE in CHIVES_KITTY_HAS_ACCOUNT_PET_20211230.items():
            if int(SEND_ADDRESS_VALUE)==1:
                SEND_ADDRESS_KEY_CACHE.append(SEND_ADDRESS_KEY)
                SEND_ADDRESS_KEY = str(SEND_ADDRESS_KEY.decode("utf-8"))
                print(SEND_ADDRESS_KEY)
                SEND_ADDRESS_KEY_ARRAY = SEND_ADDRESS_KEY.split("____")
                #print(SEND_ADDRESS_KEY_ARRAY)
                ADDRESS_NUMBER = ADDRESS_NUMBER + 1
                #处理金额和地址
                SendToAmount = uint64(SEND_ADDRESS_KEY_ARRAY[3])
                SendToAmount = 5678
                SendToAddress = str(SEND_ADDRESS_KEY_ARRAY[1])
                #SendToAddress = str("xcc15ts4mhawhl047jz70zqqcnwq366rm9wu205xv89vcpurnxwsfhfspguy94")
                SendToPuzzleHash = decode_puzzle_hash(SendToAddress).hex()
                #print("SendToPuzzleHash======================")
                #print(SendToPuzzleHash)
                #print(type(SendToPuzzleHash))
                SendToAmountArray.append(SendToAmount)
                SendToPuzzleHashArray.append(hexstr_to_bytes(SendToPuzzleHash))
                SendToMemosArray.append("")
                if ADDRESS_NUMBER>2:
                    break;
        print(f"SendToAmountArray:{SendToAmountArray}")
        #print(SendToPuzzleHashArray)
        #return;
        fee = uint64(19)
        
        
        #print("===========================================================================================")
        
        #SendToAmount = uint64(1)
        #SendToPuzzleHash = hexstr_to_bytes("61d1f3efb8e1e0c3e8e21f19714cc22c5b1b17099f059dae19f05db922706e43")
        #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
        
        #查询未花费记录
        #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
        cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
        rows = await cursor.fetchall()
        coinList = []
        CurrentCoinAmount = 0
        LINEAGE_PROOF_PARENT_PH = []
        CHIVES_CAT_COIN_NAME_IS_USED_ARRAY  = []
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
                if(CurrentCoinAmount>SendToAmount):
                    break
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
        await db_connection.close()
        
        if len(coinList)==0:
            print("ERROR TRIP===============================")
            print("Not select any one coin to send")
            return 
        
        
        SendToAmountArrayLP,SendToPuzzleHashArrayLP,coinListLP,SendToMemosArrayLP  = await self.push_transaction_Liquidity_Pool()
        
        #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
        generate_signed_transaction_cat = await self.generate_signed_transaction_cat(
            amounts=SendToAmountArray,
            puzzle_hashes=SendToPuzzleHashArray,
            fee=fee,
            coins=coinList,
            memos=SendToMemosArray,
            amountsLP=SendToAmountArrayLP,
            puzzle_hashesLP=SendToPuzzleHashArrayLP,
            coinsLP=coinListLP,
            memosLP=SendToMemosArrayLP,
        )
        print(f"generate_signed_transaction_cat:{generate_signed_transaction_cat.name()}")
        
        #提交交易记录到区块链网络
        push_tx_cat = await client_node.push_tx(generate_signed_transaction_cat)
        
        print("push_tx_cat=====================================================")
        print(push_tx_cat)
        #{'status': 'SUCCESS', 'success': True}
        if push_tx_cat['status']=="SUCCESS" and push_tx_cat['success']==True:
            #业务逻辑,标记已经发送过的记录
            for SEND_ADDRESS_KEY_CACHE_KEY in SEND_ADDRESS_KEY_CACHE:
                r.hset("CHIVES_KITTY_HAS_ACCOUNT_PET_20211230",SEND_ADDRESS_KEY_CACHE_KEY,1)
            #作废已经花费过的COIN
            for CHIVES_CAT_COIN_NAME_IS_USED_KEY in CHIVES_CAT_COIN_NAME_IS_USED_ARRAY:
                r.hset("CHIVES_CAT_COIN_NAME_IS_USED",CHIVES_CAT_COIN_NAME_IS_USED_KEY,1)
            for CHIVES_CAT_COIN_NAME_IS_USED_KEY in self.CHIVES_COIN_NAME_IS_USED_ARRAY:
                r.hset("CHIVES_CAT_COIN_NAME_IS_USED",CHIVES_CAT_COIN_NAME_IS_USED_KEY,1)
        #print(type(push_tx_cat))
        
        #关闭结点连接
        client_node.close()
        await client_node.await_closed()
        print()
        print()

    async def  push_transaction_Liquidity_Pool(self):
        CAT_ASSET_ID                                    = "3e3a7614a02d9714a21927ef99c7ef9bf8270e374dc6ecc48f2619cbc70c4ddc"
        self.limitations_program_hash_Liquidity_Pool    = hexstr_to_bytes(CAT_ASSET_ID)
        # 第二个KITTY账户 Liquidity_Pool
        mnemonic = ""
        entropy = bytes_from_mnemonic(mnemonic)
        seed = mnemonic_to_seed(mnemonic, "")
        self.private_key_Liquidity_Pool = AugSchemeMPL.key_gen(seed)
        fingerprint = self.private_key_Liquidity_Pool.get_g1().get_fingerprint()
        
        #得到指定账户的300个地址.
        AllPuzzleHashArray = []
        for i in range(0, 5):
            private = master_sk_to_wallet_sk(self.private_key_Liquidity_Pool, i)
            pubkey = private.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            puzzle_hash = str(puzzle.get_tree_hash())
            #AllPuzzleHashArray.append(puzzle_hash);
            
            limitations_program_hash_Liquidity_Pool = hexstr_to_bytes(CAT_ASSET_ID)
            inner_puzzle = puzzle_for_pk(bytes(pubkey))
            cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash_Liquidity_Pool, inner_puzzle)
            cc_puzzle_hash = cc_puzzle.get_tree_hash()
            AllPuzzleHashArray.append(str(cc_puzzle_hash))
            #把CAT_PH转换为INNER_PH
            self.inner_puzzle_for_cc_puzhash[str(cc_puzzle_hash)] = inner_puzzle
            #缓存找零地址
            if i==0:
                self.get_new_inner_hash = puzzle_hash
                self.get_new_cc_puzzle_hash = str(cc_puzzle_hash)
            #缓存公钥和私钥
            self.get_keys[puzzle_hash] = {'pubkey':pubkey,'private':private}           
        
        for i in range(0, 5):
            private = master_sk_to_wallet_sk_unhardened(self.private_key_Liquidity_Pool, i)
            pubkey = private.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))            
            puzzle_hash = str(puzzle.get_tree_hash())
            #AllPuzzleHashArray.append(puzzle_hash);
            
            limitations_program_hash_Liquidity_Pool = hexstr_to_bytes(CAT_ASSET_ID)
            inner_puzzle = puzzle_for_pk(bytes(pubkey))
            cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash_Liquidity_Pool, inner_puzzle)
            cc_puzzle_hash = cc_puzzle.get_tree_hash()
            AllPuzzleHashArray.append(str(cc_puzzle_hash))
            #把CAT_PH转换为INNER_PH
            self.inner_puzzle_for_cc_puzhash[str(cc_puzzle_hash)] = inner_puzzle
            if i==0:
                self.get_new_inner_hash = puzzle_hash
                self.get_new_cc_puzzle_hash = str(cc_puzzle_hash)
            #缓存公钥和私钥
            self.get_keys[puzzle_hash] = {'pubkey':pubkey,'private':private}
            
        #print("self.get_new_inner_hash===============================")
        #print(self.get_new_inner_hash)
        #print("AllPuzzleHashArray===============================")
        #print(AllPuzzleHashArray)
        #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
        separator = "','"
        AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
        AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
        
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
        db_connection = await aiosqlite.connect("/home/wang/.chives/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
        
        #手工输入来构建参数部分代码 根据REDIS的值,一次性发送多个地址.        
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        CHIVES_KITTY_HAS_ACCOUNT_PET_20211230 = r.hgetall("CHIVES_KITTY_HAS_ACCOUNT_PET_20211230")
        ADDRESS_NUMBER = 0
        SEND_ADDRESS_KEY_CACHE = []
        SendToAmountArray = []
        SendToPuzzleHashArray = []
        SendToMemosArray = []
        for SEND_ADDRESS_KEY,SEND_ADDRESS_VALUE in CHIVES_KITTY_HAS_ACCOUNT_PET_20211230.items():
            if int(SEND_ADDRESS_VALUE)==1:
                SEND_ADDRESS_KEY_CACHE.append(SEND_ADDRESS_KEY)
                SEND_ADDRESS_KEY = str(SEND_ADDRESS_KEY.decode("utf-8"))
                print(SEND_ADDRESS_KEY)
                SEND_ADDRESS_KEY_ARRAY = SEND_ADDRESS_KEY.split("____")
                #print(SEND_ADDRESS_KEY_ARRAY)
                ADDRESS_NUMBER = ADDRESS_NUMBER + 1
                #处理金额和地址
                SendToAmount = uint64(SEND_ADDRESS_KEY_ARRAY[3])
                SendToAmount = 1234
                SendToAddress = str(SEND_ADDRESS_KEY_ARRAY[1])
                #SendToAddress = str("xcc15ts4mhawhl047jz70zqqcnwq366rm9wu205xv89vcpurnxwsfhfspguy94")
                SendToPuzzleHash = decode_puzzle_hash(SendToAddress).hex()
                #print("SendToPuzzleHash======================")
                #print(SendToPuzzleHash)
                #print(type(SendToPuzzleHash))
                SendToAmountArray.append(SendToAmount)
                SendToPuzzleHashArray.append(hexstr_to_bytes(SendToPuzzleHash))
                SendToMemosArray.append("")
                if ADDRESS_NUMBER>2:
                    break;
        print(f"SendToAmountArray:{SendToAmountArray}")
        #print(SendToPuzzleHashArray)
        #return;
        fee = uint64(19)
        
        
        #print("===========================================================================================")
        
        #SendToAmount = uint64(1)
        #SendToPuzzleHash = hexstr_to_bytes("61d1f3efb8e1e0c3e8e21f19714cc22c5b1b17099f059dae19f05db922706e43")
        #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
        
        #查询未花费记录
        #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
        cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
        rows = await cursor.fetchall()
        coinList = []
        CurrentCoinAmount = 0
        LINEAGE_PROOF_PARENT_PH = []
        CHIVES_CAT_COIN_NAME_IS_USED_ARRAY  = []
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
                if(CurrentCoinAmount>SendToAmount):
                    break
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
        #self.LINEAGE_PROOF_NAME_TO_DICT = {}
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
        await db_connection.close()
        
        if len(coinList)==0:
            print("ERROR TRIP===============================")
            print("Not select any one coin to send")
            return 
        return SendToAmountArray,SendToPuzzleHashArray,coinList,SendToMemosArray

    async def generate_signed_transaction_cat(
        self,
        amounts: List[uint64],
        puzzle_hashes: List[bytes32],
        fee: uint64 = uint64(0),
        coins: Set[Coin] = None,
        memos: Optional[List[List[bytes]]] = None,
        amountsLP: List[uint64] = None,
        puzzle_hashesLP: List[bytes32] = None,
        coinsLP: Set[Coin] = None,
        memosLP: Optional[List[List[bytes]]] = None,
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
        
        #LP
        if memosLP is None:
            memosLP = [[] for _ in range(len(puzzle_hashesLP))]

        if not (len(memosLP) == len(puzzle_hashesLP) == len(amountsLP)):
            raise ValueError("LP Memos, puzzle_hashes, and amounts must have the same length")
        
        paymentsLP = []
        for amount, puzhash, memo_list in zip(amountsLP, puzzle_hashesLP, memosLP):
            memos_with_hint = [puzhash]
            memos_with_hint.extend(memo_list)
            paymentsLP.append(Payment(puzhash, amount, memos_with_hint))
            
        unsigned_spend_bundle, chives_tx = await self.generate_unsigned_spendbundle_cat(payments, fee, coins=coins, paymentsLP=paymentsLP, coinsLP=coinsLP)
        spend_bundle = await self.sign_tx_cat(unsigned_spend_bundle)

        return spend_bundle
    
    async def create_tandem_xch_tx(
        self,
        fee: uint64,
        amount_to_claim: uint64,
        announcement_to_assert: Optional[Announcement] = None,
    ) -> Tuple[TransactionRecord, Optional[Announcement]]:
        """
        This function creates a non-CAT transaction to pay fees, contribute funds for issuance, and absorb melt value.
        It is meant to be called in `generate_unsigned_spendbundle` and as such should be called under the
        wallet_state_manager lock
        """
        announcement = None
        if fee > amount_to_claim:
            '''
            chives_coins = await self.standard_wallet.select_coins(fee)
            origin_id = list(chives_coins)[0].name()
            selected_amount = sum([c.amount for c in chives_coins])
            chives_tx = await self.standard_wallet.generate_signed_transaction(
                uint64(0),
                (await self.standard_wallet.get_new_puzzlehash()),
                fee=uint64(fee - amount_to_claim),
                coins=chives_coins,
                origin_id=origin_id,  # We specify this so that we know the coin that is making the announcement
                negative_change_allowed=False,
                announcements_to_consume=set([announcement_to_assert]) if announcement_to_assert is not None else None,
            )
            '''
            # six enemy uncle practice habit erode betray right neither angry attract scorpion limit master shoot sense obtain flock still decide tattoo rail later salute
            WalletToolStandardCoinExample = WalletToolStandardCoin(DEFAULT_CONSTANTS)
            chives_tx,CHIVES_COIN_NAME_IS_USED_ARRAY,SelectedCoinList = await WalletToolStandardCoinExample.get_standard_coin_signed_tx(SendToAmount=39,   SendToPuzzleHash='4e1c74a311290f3efa129593041cbb21b07db83aae62ddeaa03f5d088f6312d7',fee=fee,mnemonic="")
            print(f"chives_tx:{chives_tx.name()}")
            self.CHIVES_COIN_NAME_IS_USED_ARRAY = CHIVES_COIN_NAME_IS_USED_ARRAY;
            #print(SelectedCoinList)
            print("------------------------------------------------------------------")
            
            origin_id = list(SelectedCoinList)[0].name()
            assert chives_tx.coin_spends is not None

            message = None
            for spend in chives_tx.coin_spends:
                if spend.coin.name() == origin_id:
                    conditions = spend.puzzle_reveal.to_program().run(spend.solution.to_program()).as_python()
                    for condition in conditions:
                        if condition[0] == ConditionOpcode.CREATE_COIN_ANNOUNCEMENT:
                            message = condition[1]

            assert message is not None
            announcement = Announcement(origin_id, message)
        else:
            chives_coins = await self.standard_wallet.select_coins(fee)
            selected_amount = sum([c.amount for c in chives_coins])
            chives_tx = await self.standard_wallet.generate_signed_transaction(
                uint64(selected_amount + amount_to_claim - fee),
                (await self.standard_wallet.get_new_puzzlehash()),
                coins=chives_coins,
                negative_change_allowed=True,
                announcements_to_consume=set([announcement_to_assert]) if announcement_to_assert is not None else None,
            )
            assert chives_tx.spend_bundle is not None

        return chives_tx, announcement
        
    async def generate_unsigned_spendbundle_cat(
        self,
        payments: List[Payment],
        fee: uint64 = uint64(0),
        cat_discrepancy: Optional[Tuple[int, Program]] = None,  # (extra_delta, limitations_solution)
        coins: Set[Coin] = None,
        paymentsLP: List[Payment] = None,
        coinsLP: Set[Coin] = None,
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
        assert selected_cat_amount >= starting_amount

        # Figure out if we need to absorb/melt some XCH as part of this
        regular_chives_to_claim: int = 0
        if payment_amount > starting_amount:
            fee = uint64(fee + payment_amount - starting_amount)
        elif payment_amount < starting_amount:
            regular_chives_to_claim = payment_amount

        need_chives_transaction = False
        need_chives_transaction = (fee > 0 or regular_chives_to_claim > 0) and (fee - regular_chives_to_claim != 0)
        print(f"need_chives_transaction:{need_chives_transaction}")
        
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
                if need_chives_transaction:
                    if fee > regular_chives_to_claim:
                        announcement = Announcement(coin.name(), b"$", b"\xca")
                        chives_tx, _ = await self.create_tandem_xch_tx(
                            fee, uint64(regular_chives_to_claim), announcement_to_assert=announcement
                        )
                        innersol = self.make_solution_cat(
                            primaries=primaries, coin_announcements={announcement.message}
                        )
                    #elif regular_chives_to_claim > fee:
                    #    chives_tx, _ = await self.create_tandem_xch_tx(fee, uint64(regular_chives_to_claim))
                    #    innersol = self.standard_wallet.make_solution_cat(
                    #        primaries=primaries, coin_announcements_to_assert={announcement.name()}
                    #    )
                else:
                    innersol = self.make_solution_cat(primaries=primaries)
            else:
                innersol = self.make_solution_cat()
            inner_puzzle = self.inner_puzzle_for_cc_puzhash[str(coin.puzzle_hash)]
            lineage_proof = self.LINEAGE_PROOF_NAME_TO_DICT[str(coin.parent_coin_info)]
            assert lineage_proof is not None
            print("coin===============================")
            print(coin)
            print("self.limitations_program_hash===============================")
            print(self.limitations_program_hash)
            print("inner_puzzle===============================")
            print(inner_puzzle)
            print("innersol===============================")
            print(innersol)
            print("limitations_solution===============================")
            print(limitations_solution)
            print("extra_delta===============================")
            print(extra_delta)
            print("lineage_proof===============================")
            print(lineage_proof)
            print("limitations_program_reveal===============================")
            print(limitations_program_reveal)
            
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
        #得到LP的TOKEN转移    
        spendable_cc_list_LP = await self.generate_unsigned_spendbundle_cat_LP(payments=paymentsLP,coins=coinsLP)
        #合并入花费列表
        for new_spendable_cc in spendable_cc_list_LP:
            spendable_cc_list.append(new_spendable_cc)
        #print("*************************************************************************************************")
        #print(spendable_cc_list_LP)
        
        cat_spend_bundle = unsigned_spend_bundle_for_spendable_ccs(CC_MOD, spendable_cc_list)
        chives_spend_bundle = SpendBundle([], G2Element())
        if chives_tx is not None and chives_tx is not None:
            chives_spend_bundle = chives_tx

        return (
            SpendBundle.aggregate(
                [
                    cat_spend_bundle,
                    chives_spend_bundle,
                ]
            ),
            chives_tx,
        )
        
    async def generate_unsigned_spendbundle_cat_LP(
        self,
        payments: List[Payment],
        fee: uint64 = uint64(0),
        cat_discrepancy: Optional[Tuple[int, Program]] = None,  # (extra_delta, limitations_solution)
        coins: Set[Coin] = None,
    ) -> Tuple[SpendableCC]:
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
        assert selected_cat_amount >= starting_amount

        # Figure out if we need to absorb/melt some XCH as part of this
        regular_chives_to_claim: int = 0
        if payment_amount > starting_amount:
            fee = uint64(fee + payment_amount - starting_amount)
        elif payment_amount < starting_amount:
            regular_chives_to_claim = payment_amount

        need_chives_transaction = False
        need_chives_transaction = (fee > 0 or regular_chives_to_claim > 0) and (fee - regular_chives_to_claim != 0)
        print(f"need_chives_transaction:{need_chives_transaction}")
        
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
                if need_chives_transaction:
                    if fee > regular_chives_to_claim:
                        announcement = Announcement(coin.name(), b"$", b"\xca")
                        chives_tx, _ = await self.create_tandem_xch_tx(
                            fee, uint64(regular_chives_to_claim), announcement_to_assert=announcement
                        )
                        innersol = self.make_solution_cat(
                            primaries=primaries, coin_announcements={announcement.message}
                        )
                    #elif regular_chives_to_claim > fee:
                    #    chives_tx, _ = await self.create_tandem_xch_tx(fee, uint64(regular_chives_to_claim))
                    #    innersol = self.standard_wallet.make_solution_cat(
                    #        primaries=primaries, coin_announcements_to_assert={announcement.name()}
                    #    )
                else:
                    innersol = self.make_solution_cat(primaries=primaries)
            else:
                innersol = self.make_solution_cat()
            inner_puzzle = self.inner_puzzle_for_cc_puzhash[str(coin.puzzle_hash)]
            lineage_proof = self.LINEAGE_PROOF_NAME_TO_DICT[str(coin.parent_coin_info)]
            assert lineage_proof is not None
            print("coin===============================")
            print(coin)
            print("self.limitations_program_hash===============================")
            print(self.limitations_program_hash)
            print("inner_puzzle===============================")
            print(inner_puzzle)
            print("innersol===============================")
            print(innersol)
            print("limitations_solution===============================")
            print(limitations_solution)
            print("extra_delta===============================")
            print(extra_delta)
            print("lineage_proof===============================")
            print(lineage_proof)
            print("limitations_program_reveal===============================")
            print(limitations_program_reveal)
            
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
        return spendable_cc_list
        
        
    def make_solution_cat(
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
    
    async def sign_tx_cat(self, spend_bundle: SpendBundle) -> SpendBundle:
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
    async def push_tx_cat(self,generate_signed_transaction_cat):
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx_cat(generate_signed_transaction_cat)
            return push_res
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
    

















class WalletToolStandardCoin:
    next_address = 0
    pubkey_num_lookup: Dict[bytes, uint32] = {}

    def __init__(self, constants: ConsensusConstants, sk: Optional[PrivateKey] = None):
        
        
        self.constants = constants
        self.current_balance = 0
        self.my_utxos: set = set()
        self.generator_lookups: Dict = {}
        self.puzzle_pk_cache: Dict = {}
        
        #print(constants)
        #print()
        #print()
        #print()
     
    async def  get_standard_coin_signed_tx(self,SendToAmount,SendToPuzzleHash,fee,mnemonic):           
        #mnemonic = generate_mnemonic()
        #when you want to make a send transaction, you must need a account.
        #here it is to fill the mnemonic works and to make a account
        #mnemonic = ""
        entropy = bytes_from_mnemonic(mnemonic)
        seed = mnemonic_to_seed(mnemonic, "")
        self.private_key = AugSchemeMPL.key_gen(seed)
        fingerprint = self.private_key.get_g1().get_fingerprint()
        
        #得到指定账户的300个地址.
        AllPuzzleHashArray = []
        for i in range(0, 10):
            pubkey = master_sk_to_wallet_sk(self.private_key, i).get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            puzzle_hash = str(puzzle.get_tree_hash())
            AllPuzzleHashArray.append(puzzle_hash);
            
        print(AllPuzzleHashArray)
        #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
        separator = "','"
        AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
        AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
        
        
        #连接数据库
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        db_connection = await aiosqlite.connect("/home/wang/.chives/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
        
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        
        #手工输入来构建参数部分代码
        SendToAmount        = uint64(SendToAmount)
        fee                 = uint64(fee)
        #SendToPuzzleHash    = AllPuzzleHashArray[1]
        
        #查询未花费记录
        cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
        rows = await cursor.fetchall()
        SelectedCoinList = []
        CurrentCoinAmount = 0
        CHIVES_COIN_NAME_IS_USED_ARRAY = []        
        for row in rows:
            coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
            #查询该COIN是否被花费
            if r.hget("CHIVES_CAT_COIN_NAME_IS_USED",str(coin.name())) is None:
                CurrentCoinAmount += uint64.from_bytes(row[7])
                SelectedCoinList.append(coin)
                #print(row) 
                #标记该COIN已经被花费过,不能再次使用
                CHIVES_COIN_NAME_IS_USED_ARRAY.append(str(coin.name()))
                if(CurrentCoinAmount>SendToAmount):
                    break
        print(f"fee:{fee}")
        await cursor.close()
        await db_connection.close()
        if(len(SelectedCoinList)==0):
            return ''
        
        #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
        generate_signed_transaction = self.generate_signed_transaction_multiple_coins(
            SendToAmount,
            SendToPuzzleHash,
            SelectedCoinList,
            {},
            fee,
        )
        return generate_signed_transaction,CHIVES_COIN_NAME_IS_USED_ARRAY,SelectedCoinList
        
        #提交交易记录到区块链网络
        '''
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx(generate_signed_transaction)
            print(f"TXID:{generate_signed_transaction.name()}")
            
            if push_res['status']=="SUCCESS" and push_res['success']==True:
                #作废已经花费过的COIN
                for CHIVES_CAT_COIN_NAME_IS_USED_KEY in CHIVES_COIN_NAME_IS_USED_ARRAY:
                    r.hset("CHIVES_CAT_COIN_NAME_IS_USED",CHIVES_CAT_COIN_NAME_IS_USED_KEY,1)
                print(push_res)
            return generate_signed_transaction,CHIVES_COIN_NAME_IS_USED_ARRAY
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
        '''
            
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
                    print('===================')
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
        new_puzzle_hash: bytes32,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]],
        fee: int = 0,
        secret_key: Optional[PrivateKey] = None,
    ) -> List[CoinSpend]:
        spends = []
        
        spend_value = sum([c.amount for c in coins])

        if ConditionOpcode.CREATE_COIN not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN] = []
        if ConditionOpcode.CREATE_COIN_ANNOUNCEMENT not in condition_dic:
            condition_dic[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT] = []

        output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [hexstr_to_bytes(new_puzzle_hash), int_to_bytes(amount)])
        condition_dic[output.opcode].append(output)
        amount_total = sum(int_from_bytes(cvp.vars[1]) for cvp in condition_dic[ConditionOpcode.CREATE_COIN])
        change = spend_value - amount_total - fee
        if change > 0:
            change_puzzle_hash = self.get_new_puzzlehash()
            change_output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [change_puzzle_hash, int_to_bytes(change)])
            condition_dic[output.opcode].append(change_output)

        secondary_coins_cond_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = dict()
        secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT] = []
        
        for n, coin in enumerate(coins):
            puzzle_hash = coin.puzzle_hash
            print(n);
            print(coin);
            print('----------------------')
            if secret_key is None:
                secret_key = self.get_private_key_for_puzzle_hash(puzzle_hash)
            pubkey = secret_key.get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
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

    def sign_transaction(self, coin_solutions: List[CoinSpend]) -> SpendBundle:
        signatures = []
        solution: Program
        puzzle: Program
        for coin_solution in coin_solutions:  # type: ignore # noqa
            secret_key = self.get_private_key_for_puzzle_hash(coin_solution.coin.puzzle_hash)
            synthetic_secret_key = calculate_synthetic_secret_key(secret_key, DEFAULT_HIDDEN_PUZZLE_HASH)
            err, con, cost = conditions_for_solution(
                coin_solution.puzzle_reveal, coin_solution.solution, self.constants.MAX_BLOCK_COST_CLVM
            )
            if not con:
                raise ValueError(err)
            conditions_dict = conditions_by_opcode(con)

            for _, msg in pkm_pairs_for_conditions_dict(
                conditions_dict, bytes(coin_solution.coin.name()), self.constants.AGG_SIG_ME_ADDITIONAL_DATA
            ):
                signature = AugSchemeMPL.sign(synthetic_secret_key, msg)
                signatures.append(signature)
        aggsig = AugSchemeMPL.aggregate(signatures)
        spend_bundle = SpendBundle(coin_solutions, aggsig)
        return spend_bundle

    def generate_signed_transaction_multiple_coins(
        self,
        amount: uint64,
        new_puzzle_hash: bytes32,
        coins: List[Coin],
        condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = None,
        fee: int = 0,
    ) -> SpendBundle:
        if condition_dic is None:
            condition_dic = {}
        transaction = self.generate_unsigned_transaction(amount, new_puzzle_hash, coins, condition_dic, fee)
        assert transaction is not None
        return self.sign_transaction(transaction)

    
if __name__ == "__main__":
    wt = WalletToolCat(DEFAULT_CONSTANTS)
    asyncio.run(wt.push_transaction_cat())
    
    #WalletToolStandardCoinExample = WalletToolStandardCoin(DEFAULT_CONSTANTS)
    #asyncio.run(WalletToolStandardCoinExample.push_transaction())
    
