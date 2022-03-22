from chia.util.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.wallet import Wallet
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.cmds.wallet_funcs import get_wallet
from chia.rpc.wallet_rpc_client import WalletRpcClient
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.config import load_config
from chia.util.ints import uint16
from typing import Optional, Tuple, Iterable, Union, List
import io
import asyncio
from blspy import G2Element

from chia.types.blockchain_format.program import INFINITE_COST
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.spend_bundle import CoinSpend, SpendBundle
from chia.util.condition_tools import conditions_dict_for_solution
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.cc_loader import CC_MOD
from chia.wallet.sign_coin_spends import sign_coin_spends

NULL_SIGNATURE = G2Element()

from blspy import PrivateKey
from chia.wallet.derive_keys import master_sk_to_wallet_sk, master_sk_to_wallet_sk_unhardened
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
)

from chia.consensus.default_constants import DEFAULT_CONSTANTS
MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM
AGG_SIG_ME_ADDITIONAL_DATA = DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA

from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk
from chia.util.hash import std_hash
from chia.types.announcement import Announcement

from chia.wallet.cc_wallet.cc_utils import (
    CC_MOD,
    SpendableCC,
    construct_cc_puzzle,
    unsigned_spend_bundle_for_spendable_ccs,
    match_cat_puzzle,
)

from chia.wallet.lineage_proof import LineageProof

import time
import json
import unittest
import yaml
from typing import List, Optional, Tuple
from chia.util.byte_types import hexstr_to_bytes
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL
from chia.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chia.consensus.coinbase import create_puzzlehash_for_pk
from chia.util.keychain import generate_mnemonic, mnemonic_to_seed, bytes_from_mnemonic
import sys


from chia.consensus.constants import ConsensusConstants

from chia.rpc.full_node_rpc_api import FullNodeRpcApi
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.config import load_config
from chia.util.ints import uint16
from chia.util.misc import format_bytes

import asyncio
import dataclasses
import time
import traceback
import aiosqlite
import redis
from secrets import token_bytes
from typing import Callable, Dict, List, Optional, Tuple, Set

from blspy import AugSchemeMPL, G2Element
from chiabip158 import PyBIP158

import chia.server.ws_connection as ws
from chia.consensus.block_creation import create_unfinished_block
from chia.consensus.block_record import BlockRecord
from chia.consensus.pot_iterations import calculate_ip_iters, calculate_iterations_quality, calculate_sp_iters
from chia.full_node.bundle_tools import best_solution_generator_from_template, simple_solution_generator
from chia.full_node.full_node import FullNode
from chia.full_node.mempool_check_conditions import get_puzzle_and_solution_for_coin
from chia.full_node.signage_point import SignagePoint
from chia.protocols import farmer_protocol, full_node_protocol, introducer_protocol, timelord_protocol, wallet_protocol
from chia.protocols.full_node_protocol import RejectBlock, RejectBlocks
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.protocols.wallet_protocol import (
    PuzzleSolutionResponse,
    RejectHeaderBlocks,
    RejectHeaderRequest,
    CoinState,
    RespondSESInfo,
)
from chia.server.outbound_message import Message, make_msg
from chia.types.blockchain_format.coin import Coin, hash_coin_list
from chia.types.blockchain_format.pool_target import PoolTarget
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.blockchain_format.sub_epoch_summary import SubEpochSummary
from chia.types.coin_record import CoinRecord
from chia.types.end_of_slot_bundle import EndOfSubSlotBundle
from chia.types.full_block import FullBlock
from chia.types.generator_types import BlockGenerator
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.types.mempool_item import MempoolItem
from chia.types.peer_info import PeerInfo
from chia.types.unfinished_block import UnfinishedBlock
from chia.util.api_decorators import api_request, peer_required, bytes_required, execute_task, reply_type
from chia.util.generator_tools import get_block_header
from chia.util.hash import std_hash
from chia.util.ints import uint8, uint32, uint64, uint128
from chia.util.merkle_set import MerkleSet


class WalletTool:
    next_address = 0
    
    def __init__(self, constants: ConsensusConstants, sk: Optional[PrivateKey] = None):
        self.constants = constants
        self.current_balance = 0
        self.my_utxos: set = set()
        self.generator_lookups: Dict = {}
        self.puzzle_pk_cache: Dict = {}
        
    async def push_tx(self):
        
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            
            '''
            CREATE TABLE asset_token_record (
                height            BIGINT,
                header_hash       CHAR (64),
                ASSET_ID          CHAR (64),
                inner_puzzle_hash CHAR (64),
                cat_puzzle_hash   CHAR (64),
                parent_coin_info  CHAR (64),
                amount            BIGINT,
                timestamp         BIGINT,
                coin_name         CHAR (64) PRIMARY KEY
            );
            '''
            
            EveryTimeDealBlockNumber = 50
            #FromBlockHeight = 830142     

            pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
            r = redis.Redis(connection_pool=pool)
            
            
            #CHIVES_WALLET_CLI_LOCKING = r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_TOKEN_RECORD_MAKE_CHIA.py",0)
            CHIVES_WALLET_CLI_LOCKING = r.hget("CHIVES_WALLET_CLI_LOCKING","CAT_TOKEN_RECORD_MAKE_CHIA.py")
            if CHIVES_WALLET_CLI_LOCKING is None:
                CHIVES_WALLET_CLI_LOCKING = 0
            CHIVES_WALLET_CLI_LOCKING = int(CHIVES_WALLET_CLI_LOCKING)
            #上一个任务没有执行完成,请等待
            要求等待时间 = 36000
            if int(time.time()) - CHIVES_WALLET_CLI_LOCKING < 要求等待时间 :
                print("上一个任务没有执行完成,请等待秒数:")
                print(要求等待时间 - int(time.time()) + CHIVES_WALLET_CLI_LOCKING)
                import os
                os._exit(0)
                return 
            #开始执行,标记为当前时间
            if CHIVES_WALLET_CLI_LOCKING == 0:            
                r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_TOKEN_RECORD_MAKE_CHIA.py", int(time.time()) )    
            
            if ( int(time.time()) - CHIVES_WALLET_CLI_LOCKING ) > 要求等待时间:
                #执行时间超过规定的时间间隔,已经超时,可以再次执行
                r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_TOKEN_RECORD_MAKE_CHIA.py", int(time.time()) )
            
            print(f"CHIVES_WALLET_CLI_LOCKING: {CHIVES_WALLET_CLI_LOCKING}")
            
            
            #得需要得到某一个代币的初始发行的COIN
            随便一个COIN名称  = "78567e362b6451cda7b6634cfa9a0390177a2fb6daa4ab66c034b4d7bea3f3d0"
            
            COUNTER = 0
            是否初始发行的COIN = False
            while 是否初始发行的COIN == False:
                COUNTER = COUNTER+1
                coin_id = 随便一个COIN名称                
                Coin_Infor = await client_node.get_coin_record_by_name(hexstr_to_bytes(coin_id))
                #print(Coin_Infor.coin.parent_coin_info)
                当前币的父币PH = Coin_Infor.coin.parent_coin_info
                父币信息 = await client_node.get_coin_record_by_name(当前币的父币PH)
                当前币的父币的COINNAME = str(父币信息.coin.name())
                当前币的父币的SPENT_INDEX = 父币信息.spent_block_index
                get_block_record_by_height = await client_node.get_block_record_by_height(父币信息.confirmed_block_index)
                header_hash = get_block_record_by_height.header_hash
                #print(父币信息)
                #print(当前币的父币的COINNAME)
                #print(当前币的父币的SPENT_INDEX)
                coin_id = str(当前币的父币的COINNAME)
                print("=======================================================")
                print(f"COUNTER:{COUNTER} 随便一个COIN名称:{随便一个COIN名称}")
                print(f"父币的COINNAME:{当前币的父币的COINNAME} 父币的SPENT_INDEX:{当前币的父币的SPENT_INDEX}")
                随便一个COIN名称 = 当前币的父币的COINNAME
                get_puzzle_and_solution = await client_node.get_puzzle_and_solution(hexstr_to_bytes(coin_id), 当前币的父币的SPENT_INDEX)
                #print(get_puzzle_and_solution)
                if get_puzzle_and_solution is not None:
                    matched, curried_args = match_cat_puzzle(get_puzzle_and_solution.puzzle_reveal)
                    if matched:        
                        mod_hash, genesis_coin_checker_hash, inner_puzzle = curried_args
                        ASSET_ID = str(genesis_coin_checker_hash)[2:]
                        inner_puzzle_hash = str(inner_puzzle.get_tree_hash())
                        print("---------------------------------------------------------")
                        print(f"height: {父币信息.confirmed_block_index}")
                        print(f"header_hash: {header_hash}")
                        print(f"ASSET_ID: {ASSET_ID}")
                        print(f"inner_puzzle_hash: {inner_puzzle_hash}")
                        print(f"cat_puzzle_hash: {父币信息.coin.puzzle_hash}")
                        print(f"parent_coin_info: {父币信息.coin.parent_coin_info}")
                        print(f"amount: {父币信息.coin.amount}")
                        print(f"timestamp: {get_block_record_by_height.timestamp}")
                        print(f"coin_name: {coin_id}")
                        r.set("CHIVES_WALLET_ASSETID_CURRENT_DOGIN", coin_id )
                        
                    else:
                        是否初始发行的COIN = True
            
            是否有初始COIN = r.get("CHIVES_WALLET_ASSETID_CURRENT_DOGIN")
            print("********************************************************")
            初始发行的COIN的NAME = str(是否有初始COIN.decode('utf-8'))
            print(f"初始发行的COIN的NAME:{初始发行的COIN的NAME}")
            print("********************************************************")
            
            #import os
            #os._exit(0)
            #return 
            
            '''
            初始发行的COIN的NAME = "532d056b1c72af40ec43c8d4bd2f5cb1959936ff660f9e4468d742014087fc1f" #CryptoShibe Gold
            初始发行的COIN的NAME = "38f2109b2ce9a34edd8dd0ccaa03023f19aaadf18856cac47fcfd9c3507e36db" #TEST001
            初始发行的COIN的NAME = "be16d5ce958c35648c27bea0989293d990d8bd1764cd6bc45329ea862ee4c0f6" #ROSE
            初始发行的COIN的NAME = "6343f0738ccdf567b02b8f5e35d9a1a0eec2f8924b2322e0de670a5e38c36a8f" #Spacebucks
            初始发行的COIN的NAME = "0a50b946d456ea07b8658d2cb4c64e31eb79d2285e660bb4eb2320546e5466ef" #Marmot
            '''
            
            待处理COIN的NAME = []
            待处理COIN的NAME.append(初始发行的COIN的NAME);
            TableRecords    = []
            
            while len(待处理COIN的NAME)>0:
                for CoinName in 待处理COIN的NAME:
                    #处理当前币的数据.不扩充数据
                    Coin_record = await client_node.get_coin_record_by_name(hexstr_to_bytes(CoinName))
                    #print(Coin_record)
                    if (Coin_record.spent):
                        #解析TOKEN的数据
                        get_block_record_by_height = await client_node.get_block_record_by_height(Coin_record.confirmed_block_index)
                        header_hash = get_block_record_by_height.header_hash
                        get_puzzle_and_solution = await client_node.get_puzzle_and_solution(Coin_record.coin.name(), Coin_record.spent_block_index)
                        #print(get_puzzle_and_solution)
                        if get_puzzle_and_solution is not None:
                            matched, curried_args = match_cat_puzzle(get_puzzle_and_solution.puzzle_reveal)
                            if matched:        
                                mod_hash, genesis_coin_checker_hash, inner_puzzle = curried_args
                                ASSET_ID = str(genesis_coin_checker_hash)[2:]
                                inner_puzzle_hash = str(inner_puzzle.get_tree_hash())
                                print("---------------------------------------------------------")
                                print(f"len(待处理COIN的NAME): {len(待处理COIN的NAME)}")
                                print(f"height: {Coin_record.confirmed_block_index}")
                                print(f"header_hash: {header_hash}")
                                print(f"ASSET_ID: {ASSET_ID}")
                                print(f"inner_puzzle_hash: {inner_puzzle_hash}")
                                print(f"cat_puzzle_hash: {Coin_record.coin.puzzle_hash}")
                                print(f"parent_coin_info: {Coin_record.coin.parent_coin_info}")
                                print(f"amount: {Coin_record.coin.amount}")
                                print(f"timestamp: {get_block_record_by_height.timestamp}")
                                print(f"coin_name: {Coin_record.coin.name()}")                                    
                                
                                #height|header_hash|ASSET_ID|inner_puzzle_hash|cat_puzzle_hash|parent_coin_info|amount|timestamp|coin_name|add_or_del
                                sql = "INSERT OR REPLACE INTO asset_token_record VALUES("+str(Coin_record.confirmed_block_index)+", '"+str(header_hash)+"', '"+str(ASSET_ID)+"', '"+str(inner_puzzle_hash)+"', '"+str(Coin_record.coin.puzzle_hash)+"', '"+str(Coin_record.coin.parent_coin_info)+"', '"+str(Coin_record.coin.amount)+"', '"+str(get_block_record_by_height.timestamp)+"', '"+str(Coin_record.coin.name())+"', '"+str("")+"')";
                                TableRecords.append(sql)
                    #print(Coin_Infor)
                    #得到子币信息,扩充数据
                    Coin_Infor = await client_node.get_coin_records_by_parent_ids([hexstr_to_bytes(CoinName)])
                    for Coin_record in Coin_Infor:
                        if (Coin_record.spent):
                            print(Coin_record.coin.name())
                            待处理COIN的NAME.append(str(Coin_record.coin.name()))
                        else:
                            print("2 Not Spent")
                    #print(Coin_Infor)
                    待处理COIN的NAME.remove(CoinName)
            #数据库连接池
            db_connection = await aiosqlite.connect("/home/wang/.chia/standalone_wallet/db/mainnet_asset_token2.sqlite")
            #写入数据表
            for sql in TableRecords:
                cursor = await db_connection.execute(sql)
                await cursor.close()     
            #所有的区块都处理完成以后,提交到数据库
            await db_connection.commit()
            #所有的区块都处理完成以后,才关闭连接
            await db_connection.close()
            
            import os
            os._exit(0)
            return 
            
            

            
            
            #把时间设置为0,取消LOCK
            r.hset("CHIVES_WALLET_CLI_LOCKING","CAT_TOKEN_RECORD_MAKE_CHIA.py", 0 )        
            #所有的区块都处理完成以后,提交到数据库
            await db_connection.commit()
            #所有的区块都处理完成以后,才关闭连接
            await db_connection.close()
            r.connection_pool.disconnect()
            '''
            coin_id = hexstr_to_bytes("621be682aeb07b8bbd7d57e7fa1e02d35ea525e6892dbfe1b05ddaf06e0a32d6")
            height = 829094
            get_puzzle_and_solution = await client_node.get_puzzle_and_solution(coin_id, height)
            matched, curried_args = match_cat_puzzle(get_puzzle_and_solution.puzzle_reveal)
            if matched:        
                mod_hash, genesis_coin_checker_hash, inner_puzzle = curried_args
                ASSET_ID = str(genesis_coin_checker_hash)[2:]
                inner_puzzle_hash = str(inner_puzzle.get_tree_hash())
                print(ASSET_ID)
                print(inner_puzzle_hash)
            '''
            
        except Exception as e:
            print(f"Exception {e}")
        finally:
            client_node.close()
            await client_node.await_closed()
        
        '''
        puzzle = '0xff02ffff01ff02ffff01ff02ff5effff04ff02ffff04ffff04ff05ffff04ffff0bff2cff0580ffff04ff0bff80808080ffff04ffff02ff17ff2f80ffff04ff5fffff04ffff02ff2effff04ff02ffff04ff17ff80808080ffff04ffff0bff82027fff82057fff820b7f80ffff04ff81bfffff04ff82017fffff04ff8202ffffff04ff8205ffffff04ff820bffff80808080808080808080808080ffff04ffff01ffffffff81ca3dff46ff0233ffff3c04ff01ff0181cbffffff02ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04ffff0bff22ffff0bff2cff3480ffff0bff22ffff0bff22ffff0bff2cff5c80ff0980ffff0bff22ff0bffff0bff2cff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ff0bffff01ff02ffff03ffff09ffff02ff2effff04ff02ffff04ff13ff80808080ff820b9f80ffff01ff02ff26ffff04ff02ffff04ffff02ff13ffff04ff5fffff04ff17ffff04ff2fffff04ff81bfffff04ff82017fffff04ff1bff8080808080808080ffff04ff82017fff8080808080ffff01ff088080ff0180ffff01ff02ffff03ff17ffff01ff02ffff03ffff20ff81bf80ffff0182017fffff01ff088080ff0180ffff01ff088080ff018080ff0180ffff04ffff04ff05ff2780ffff04ffff10ff0bff5780ff778080ff02ffff03ff05ffff01ff02ffff03ffff09ffff02ffff03ffff09ff11ff7880ffff0159ff8080ff0180ffff01818f80ffff01ff02ff7affff04ff02ffff04ff0dffff04ff0bffff04ffff04ff81b9ff82017980ff808080808080ffff01ff02ff5affff04ff02ffff04ffff02ffff03ffff09ff11ff7880ffff01ff04ff78ffff04ffff02ff36ffff04ff02ffff04ff13ffff04ff29ffff04ffff0bff2cff5b80ffff04ff2bff80808080808080ff398080ffff01ff02ffff03ffff09ff11ff2480ffff01ff04ff24ffff04ffff0bff20ff2980ff398080ffff010980ff018080ff0180ffff04ffff02ffff03ffff09ff11ff7880ffff0159ff8080ff0180ffff04ffff02ff7affff04ff02ffff04ff0dffff04ff0bffff04ff17ff808080808080ff80808080808080ff0180ffff01ff04ff80ffff04ff80ff17808080ff0180ffffff02ffff03ff05ffff01ff04ff09ffff02ff26ffff04ff02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff0bff22ffff0bff2cff5880ffff0bff22ffff0bff22ffff0bff2cff5c80ff0580ffff0bff22ffff02ff32ffff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff8080808080ffff0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01ff0bff2cff058080ff0180ffff04ffff04ff28ffff04ff5fff808080ffff02ff7effff04ff02ffff04ffff04ffff04ff2fff0580ffff04ff5fff82017f8080ffff04ffff02ff7affff04ff02ffff04ff0bffff04ff05ffff01ff808080808080ffff04ff17ffff04ff81bfffff04ff82017fffff04ffff0bff8204ffffff02ff36ffff04ff02ffff04ff09ffff04ff820affffff04ffff0bff2cff2d80ffff04ff15ff80808080808080ff8216ff80ffff04ff8205ffffff04ff820bffff808080808080808080808080ff02ff2affff04ff02ffff04ff5fffff04ff3bffff04ffff02ffff03ff17ffff01ff09ff2dffff0bff27ffff02ff36ffff04ff02ffff04ff29ffff04ff57ffff04ffff0bff2cff81b980ffff04ff59ff80808080808080ff81b78080ff8080ff0180ffff04ff17ffff04ff05ffff04ff8202ffffff04ffff04ffff04ff24ffff04ffff0bff7cff2fff82017f80ff808080ffff04ffff04ff30ffff04ffff0bff81bfffff0bff7cff15ffff10ff82017fffff11ff8202dfff2b80ff8202ff808080ff808080ff138080ff80808080808080808080ff018080ffff04ffff01a072dec062874cd4d3aab892a0906688a1ae412b0109982e1797a170add88bdcdcffff04ffff01a03e3a7614a02d9714a21927ef99c7ef9bf8270e374dc6ecc48f2619cbc70c4ddcffff04ffff01ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0af4246a86c28ff7ce723288cf4ff9bd35e77cbbdc6d8374615a2e98e5d31ba7458fd39ef9ed2645f89b5916834036b3dff018080ff0180808080'
        pz = Program.from_bytes(hexstr_to_bytes(puzzle))
        matched, curried_args = match_cat_puzzle(pz)
        if matched:        
            mod_hash, genesis_coin_checker_hash, inner_puzzle = curried_args
            print(str(genesis_coin_checker_hash))
            print(str(inner_puzzle.get_tree_hash()))
        '''    
wt = WalletTool(DEFAULT_CONSTANTS)
asyncio.run(wt.push_tx())


