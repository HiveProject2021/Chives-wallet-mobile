import json
import time
import asyncio
import aiosqlite
import sqlite3
import logging
import redis

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
from clvm.casts import int_from_bytes, int_to_bytes
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
from pathlib import Path

from chia.wallet.derive_keys import master_sk_to_wallet_sk,master_sk_to_wallet_sk_unhardened


class WalletTool:
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
     
    async def  push_transaction(self):  
        time.sleep(50)
        pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
        r = redis.Redis(connection_pool=pool)
        #mnemonic = generate_mnemonic()
        #when you want to make a send transaction, you must need a account.
        #here it is to fill the mnemonic works and to make a account
        mnemonic = ""
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
            #print(puzzle_hash)
        '''
        for i in range(0, 10):
            pubkey = master_sk_to_wallet_sk_unhardened(self.private_key, i).get_g1()
            puzzle = puzzle_for_pk(bytes(pubkey))
            puzzle_hash = str(puzzle.get_tree_hash())
            AllPuzzleHashArray.append(puzzle_hash);
        '''    
        #print(AllPuzzleHashArray)
        #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
        separator = "','"
        AllPuzzleHashArrayText = separator.join(AllPuzzleHashArray)
        AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
        #print(AllPuzzleHashArrayText)
        
        #连接数据库
        root_path = DEFAULT_ROOT_PATH
        config = load_config(root_path, "config.yaml")
        selected = config["selected_network"]
        prefix = config["network_overrides"]["config"][selected]["address_prefix"]
        log = logging.Logger
        #db_connection = await aiosqlite.connect("/home/ubuntu/.chia/mainnet/db/blockchain_v2_testnet10.sqlite")
        db_connection = await aiosqlite.connect("/home/wang/.chia/mainnet/db/blockchain_v2_testnet10.sqlite")
        
        #手工输入来构建参数部分代码
        SendToAmount        = uint64(11)
        fee                 = uint64(0)
        SendToPuzzleHash    = "04cef8e607b69bea527f1de60b2ce9789352c94e2c36aa395d80d3bb99247bae"
        #coin = Coin(hexstr_to_bytes("944462ee5b59b8128e90b9a650f865c10000000000000000000000000005ce5d"), hexstr_to_bytes("68dffc83153d9f68f3fe89f5cf982149c7ca0f60369124a5b06a52f5a0d2ab81"), uint64(2250000000))
        
        #查询未花费记录
        #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
        cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
        rows = await cursor.fetchall()
        
        #r.delete("CHIA_DUST_ATTACK_COIN_USDED")
        print(len(rows))
        counter = 0
        counter1 = 0
        for row in rows:            
            coin = Coin(bytes32(bytes.fromhex(row[6])), bytes32(bytes.fromhex(row[5])), uint64.from_bytes(row[7]))
            CoinisUsed = r.hget("CHIA_DUST_ATTACK_COIN_USDED",coin.name());
            if CoinisUsed == None:
                coinList            = []
                CurrentCoinAmount   = 0
                CurrentCoinAmount   = uint64.from_bytes(row[7])
                coinList.append(coin)
                
                if(CurrentCoinAmount>=(SendToAmount+fee)):
                    print(f"coin.name(): {coin.name()} {CurrentCoinAmount}")
                    #coinList里面是一个数组,里面包含有的COIN对像. 这个函数可以传入多个COIN,可以实现多个输入,对应两个输出的结构.
                    generate_signed_transaction = self.generate_signed_transaction_multiple_coins(
                        SendToAmount,
                        SendToPuzzleHash,
                        coinList,
                        {},
                        fee,
                    )
                    print(str(generate_signed_transaction.name()))
                    #提交交易记录到区块链网络
                    push_res = await self.push_tx(generate_signed_transaction)
                    if  "success" in push_res and push_res['success'] == True:
                        r.hset("CHIA_DUST_ATTACK_COIN_USDED",coin.name(),1);
                        print(counter1)
                        print(push_res)
                        counter1 = counter1 +1
                    else:
                        counter = counter +1
                        print(counter)
                        print(push_res)
                    if counter >= 3:
                        break;
        
        await cursor.close()
        await db_connection.close()
        
        
        
        
        
        
    async def push_tx(self,generate_signed_transaction):
        try:
            config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
            self_hostname = config["self_hostname"]
            rpc_port = config["full_node"]["rpc_port"]
            client_node = await FullNodeRpcClient.create(self_hostname, uint16(rpc_port), DEFAULT_ROOT_PATH, config)
            push_res = await client_node.push_tx(generate_signed_transaction)
            return push_res
        except Exception as e:
            push_res = {}
            push_res['success'] = "False"
            push_res['Exception'] = e
            return push_res
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
            for child in range(0,50):
                pubkey = master_sk_to_wallet_sk(self.private_key, uint32(child)).get_g1()
                #print(type(puzzle_hash))
                #print(type(puzzle_for_pk(bytes(pubkey)).get_tree_hash()))
                #print(puzzle_hash)
                if puzzle_hash == puzzle_for_pk(bytes(pubkey)).get_tree_hash():
                    print('===================')
                    return master_sk_to_wallet_sk(self.private_key, uint32(child))
            '''        
            for child in range(0,50):
                pubkey = master_sk_to_wallet_sk_unhardened(self.private_key, uint32(child)).get_g1()
                #print(type(puzzle_hash))
                #print(type(puzzle_for_pk(bytes(pubkey)).get_tree_hash()))
                #print(puzzle_hash)
                if puzzle_hash == puzzle_for_pk(bytes(pubkey)).get_tree_hash():
                    print('===================')
                    return master_sk_to_wallet_sk_unhardened(self.private_key, uint32(child))
            '''
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

    def make_solution(self, condition_dic: Dict[ConditionOpcode, List[ConditionWithArgs]]) -> Program:
        ret = []
        #209732
        mystring = "kEx6fXBAPVkcfDxmbQ85d53Mfc07GBx0sSbX3XMqznhVv6tsfdbbePoBwb614DXl7JbZVRSzczHZXd6jvWwCEWtTj9N2tvbiNqn3sFTDva6Z99UNey73e9jKv7ap9Q"
        mystring.encode('utf-8')
        Memos = []
        Memos.append(mystring)
        for con_list in condition_dic.values():
            for cvp in con_list:
                if cvp.opcode == ConditionOpcode.CREATE_COIN:
                    ret.append(make_create_coin_condition(cvp.vars[0], cvp.vars[1], Memos))
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
            #change_puzzle_hash = self.get_new_puzzlehash()
            #print(type(change_puzzle_hash))
            #break;
            change_puzzle_hash = bytes32(bytes.fromhex("04cef8e607b69bea527f1de60b2ce9789352c94e2c36aa395d80d3bb99247bae"))
            #print(type(change_puzzle_hash))
            change_output = ConditionWithArgs(ConditionOpcode.CREATE_COIN, [change_puzzle_hash, int_to_bytes(change)])
            condition_dic[output.opcode].append(change_output)

        secondary_coins_cond_dic: Dict[ConditionOpcode, List[ConditionWithArgs]] = dict()
        secondary_coins_cond_dic[ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT] = []
        
        for n, coin in enumerate(coins):
            puzzle_hash = coin.puzzle_hash
            #print(n);
            #print(coin);
            #print('----------------------')
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

    def sign_transaction(self, coin_spends: List[CoinSpend]) -> SpendBundle:
        signatures = []
        solution: Program
        puzzle: Program
        for coin_spend in coin_spends:  # type: ignore # noqa
            secret_key = self.get_private_key_for_puzzle_hash(coin_spend.coin.puzzle_hash)
            synthetic_secret_key = calculate_synthetic_secret_key(secret_key, DEFAULT_HIDDEN_PUZZLE_HASH)
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

    #config = load_config(Path(DEFAULT_ROOT_PATH), "config.yaml")
    #testnet_agg_sig_data = config["network_overrides"]["constants"]["testnet10"]["AGG_SIG_ME_ADDITIONAL_DATA"]
    #DEFAULT_CONSTANTS = DEFAULT_CONSTANTS.replace_str_to_bytes(**{"AGG_SIG_ME_ADDITIONAL_DATA": testnet_agg_sig_data})

    wt=WalletTool(DEFAULT_CONSTANTS)
    asyncio.run(wt.push_transaction())
    
