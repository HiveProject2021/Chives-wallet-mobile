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
        time.sleep(40)
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
        mystring = "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"
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
    
