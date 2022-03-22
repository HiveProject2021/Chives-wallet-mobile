import time
import json
import unittest
import yaml
import asyncio
import aiosqlite
import sqlite3
import logging
import sys

from typing import List, Optional, Tuple
from chives.util.byte_types import hexstr_to_bytes
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL
from chives.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chives.consensus.coinbase import create_puzzlehash_for_pk
from chives.util.keychain import generate_mnemonic, mnemonic_to_seed, bytes_from_mnemonic
from chives.util.default_root import DEFAULT_ROOT_PATH
from chives.util.config import load_config
from chives.util.ints import uint16,uint64
from chives.util.misc import format_bytes

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


#根据公钥生成地址
def create_address_by_pk(pk: str, address_prefix: str) -> str:
    return encode_puzzle_hash(
        create_puzzlehash_for_pk(
            G1Element.from_bytes(hexstr_to_bytes(pk))
        ),
        address_prefix
    )

#根据公钥生成PUZZLEHASH
def pk2_puzzle_hash(pk: str) -> str:
    return create_puzzlehash_for_pk(
        G1Element.from_bytes(hexstr_to_bytes(pk))
    ).hex()

#根据PUZZLEHASH生成地址
def puzzle_hash_2address(puzzle_hash: str, address_prefix: str) -> str:
    return encode_puzzle_hash(
        hexstr_to_bytes(puzzle_hash),
        address_prefix
    )

#根据地址生成PUZZLEHASH
def address2_puzzle_hash(xch_address: str) -> str:
    return decode_puzzle_hash(xch_address).hex()

#HD路径
def derive_path(sk: PrivateKey, path: List[int]) -> PrivateKey:
    for index in path:
        sk = AugSchemeMPL.derive_child_sk(sk, index)
    return sk
    
#非分层路径
def derive_path_unhardened(sk: PrivateKey, path: List[int]) -> PrivateKey:
    for index in path:
        sk = AugSchemeMPL.derive_child_sk_unhardened(sk, index)
    return sk


async def create_account_and_address():
    prefix                      = "xcc";
    addressNumber               = 5;   
    CAT_ASSET_ID                = ""
    #mnemonicUserDefineArray     = []
    if(len(sys.argv)>=5):
        prefix                  = sys.argv[1]
        if(prefix=="xcc"):
            HDDNumber = 9699;
        else:
            HDDNumber = 8444;
        addressNumber           = int(sys.argv[2])
        mnemonicUserDefine      = sys.argv[3]
        if(mnemonicUserDefine!="" and mnemonicUserDefine is not None):
            #使用指定的助记词语
            mnemonic = mnemonicUserDefine
        else:
            #产生新的助记词语
            mnemonic = generate_mnemonic()
        #mnemonicUserDefineArray = mnemonic.split(" ");
        #entropy = bytes_from_mnemonic(mnemonic)
        CAT_ASSET_ID            = sys.argv[4]
        if(len(CAT_ASSET_ID)!=64):
            RS          = {}
            RS['code']  = 1
            RS['msg']   = "CAT_ASSET_ID lenght is error"
            y = json.dumps(RS)
            print(y)
            return 
    else:   
        RS          = {}
        RS['code']  = 2
        RS['msg']   = "Parameter number error"
        y = json.dumps(RS)
        print(y)
        return 
        
    #恢复当前文件为无指定参数状态
    sys.argv             = [sys.argv[0]];

    seed = mnemonic_to_seed(mnemonic, "")
    seed_key = AugSchemeMPL.key_gen(seed)
    masterPublicKey = seed_key.get_g1()
    fingerprint = masterPublicKey.get_fingerprint()

    #print(mnemonic);
    #print(bytes(seed).hex())
    #print(seed_key)
    #print(masterPublicKey)
    #print(fingerprint)

    RS = {}
    RS['CAT_ASSET_ID'] = CAT_ASSET_ID
    RS['mnemonic'] = mnemonic
    RS['seed'] = bytes(seed).hex()
    RS['masterPrivateKey'] = bytes(seed_key).hex()
    RS['masterPublicKey'] = bytes(masterPublicKey).hex()
    RS['fingerprint'] = fingerprint
    RS['prefix'] = prefix
    RS['addressNumber'] = addressNumber
    RS['HDDNumber'] = HDDNumber
    RS['time'] = time.time()

    #print("##################################################################")

    PairKeysDict = {}
    PairKeysDict2 = {}
    PairKeysDict5 = {}
    puzzlehashs = []
    private_keys = []
    public_keys = []
    addresses = []
    CAT_address_ALL = []

    #prefix = "xcc"
    
    #CAT_ASSET_ID = "89a3da3e4c9370f52333017e4a956dbd807e810e9c5e63bdbd9c45cdc94a6fd0"
    
    for i in range(0, addressNumber):
        path = [12381, HDDNumber, 2, i]
        child = derive_path(seed_key, path)
        child_puk = bytes(child.get_g1()).hex()
        child_prk = bytes(child).hex()
        address = create_address_by_pk(child_puk,prefix)
        puzzlehash = pk2_puzzle_hash(child_puk);
        
        limitations_program_hash = hexstr_to_bytes(CAT_ASSET_ID)
        inner_puzzle = puzzle_for_pk(bytes(child.get_g1()))
        cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash, inner_puzzle)
        PairKeys = {}
        PairKeys['index'] = i
        PairKeys['private_key'] = child_prk
        PairKeys['public_key'] = child_puk
        PairKeys['puzzlehash'] = puzzlehash
        PairKeys['address'] = address
        PairKeys['CAT_puzzlehash'] = str(cc_puzzle.get_tree_hash())
        PairKeys['CAT_address'] = encode_puzzle_hash(cc_puzzle.get_tree_hash(),prefix)
        PairKeysDict[i] = PairKeys
        #print(f"i: {i}")
        #print(f"private_key: {private_key}")
        #print(f"public_key: {public_key}")
        #print(f"address: {address}")
        CAT_address_ALL.append(PairKeys['CAT_puzzlehash'])
    RS['PairKeysDict'] = PairKeysDict
    #print(PairKeysDict)
    
    for i in range(0, addressNumber):
        path = [12381, HDDNumber, 2, i]
        child = derive_path_unhardened(seed_key, path)
        child_puk = bytes(child.get_g1()).hex()
        child_prk = bytes(child).hex()
        address = create_address_by_pk(child_puk,prefix)
        puzzlehash = pk2_puzzle_hash(child_puk);
        
        limitations_program_hash = hexstr_to_bytes(CAT_ASSET_ID)
        inner_puzzle = puzzle_for_pk(bytes(child.get_g1()))
        cc_puzzle = construct_cc_puzzle(CC_MOD, limitations_program_hash, inner_puzzle)
        PairKeys = {}
        PairKeys['index'] = i
        PairKeys['private_key'] = child_prk
        PairKeys['public_key'] = child_puk
        PairKeys['puzzlehash'] = puzzlehash
        PairKeys['address'] = address
        PairKeys['CAT_puzzlehash'] = str(cc_puzzle.get_tree_hash())
        PairKeys['CAT_address'] = encode_puzzle_hash(cc_puzzle.get_tree_hash(),prefix)
        PairKeysDict2[i] = PairKeys
        #print(f"i: {i}")
        #print(f"private_key: {private_key}")
        #print(f"public_key: {public_key}")
        #print(f"address: {address}")
        CAT_address_ALL.append(PairKeys['CAT_puzzlehash'])
    RS['PairKeysDict2'] = PairKeysDict2
    
    RS['CAT_address_ALL'] = CAT_address_ALL
    #print(CAT_address_ALL)
    
    
    y = json.dumps(RS)
    #hashkey = sha256(mnemonic.encode('utf-8')).hexdigest()
    #r.hset("chives_KEYS_LIST",hashkey,y)
    #print("##################################################################")
    print(y)
    
    '''
    #构建一个这样的结构: 'PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash','PuzzleHash'
    separator = "','"
    AllPuzzleHashArrayText = separator.join(CAT_address_ALL)
    AllPuzzleHashArrayText = "'"+AllPuzzleHashArrayText+"'"
    
    #连接数据库
    root_path = DEFAULT_ROOT_PATH
    config = load_config(root_path, "config.yaml")
    selected = config["selected_network"]
    prefix = config["network_overrides"]["config"][selected]["address_prefix"]
    log = logging.Logger
    db_connection = await aiosqlite.connect("/home/wang/.chives/standalone_wallet/db/blockchain_v1_mainnet.sqlite")
    
    #查询未花费记录
    #cursor = await db_connection.execute("SELECT * from coin_record WHERE coin_name=?", ("812f069fe739af997478857aefb04181afd91d47b565f132f5c84c23057db669",))
    cursor = await db_connection.execute("SELECT * from coin_record WHERE spent=0 and puzzle_hash in ("+AllPuzzleHashArrayText+")")
    rows = await cursor.fetchall()
    CurrentCoinAmount = 0
    for row in rows:
        CurrentCoinAmount += uint64.from_bytes(row[7])
        print(row) 
        print(CurrentCoinAmount)
    #print(rows)
    await cursor.close()
    await db_connection.close()
    '''
if __name__ == "__main__":
    asyncio.run(create_account_and_address())