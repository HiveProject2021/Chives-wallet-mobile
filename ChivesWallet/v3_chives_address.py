import time
import json
import unittest
import yaml
from typing import List, Optional, Tuple
from chives.util.byte_types import hexstr_to_bytes
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL
from chives.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chives.consensus.coinbase import create_puzzlehash_for_pk
from chives.util.keychain import generate_mnemonic, mnemonic_to_seed, bytes_from_mnemonic
import sys

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


def create_account_and_address():
    prefix                      = "xcc";
    if(len(sys.argv)>=2):
        prefix                  = sys.argv[1]
    #根据不同的前缀,加载不同的路径
    if(prefix=="xcc"):
        HDDNumber = 9699;
    else:
        HDDNumber = 8444;
    
    addressNumber               = 5;
    if(len(sys.argv)>=3):
        addressNumber           = int(sys.argv[2])

    mnemonicUserDefine          = ""
    mnemonicUserDefineArray     = []
    if len(sys.argv)>=4 and len(sys.argv[3])>10:
        mnemonicUserDefine      = sys.argv[3]
        mnemonicUserDefineArray = mnemonicUserDefine.split(" ");
        entropy = bytes_from_mnemonic(mnemonicUserDefine)
    #恢复当前文件为无指定参数状态
    sys.argv             = [sys.argv[0]];

    #print(addressNumber)
    #print(mnemonicUserDefineArray)

    if(mnemonicUserDefine!=""):
        #使用指定的助记词语
        mnemonic = mnemonicUserDefine
    else:
        #产生新的助记词语
        mnemonic = generate_mnemonic()
        
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

    #prefix = "xcc"
    
    for i in range(0, addressNumber):
        path = [12381, HDDNumber, 2, i]
        child = derive_path(seed_key, path)
        child_puk = bytes(child.get_g1()).hex()
        child_prk = bytes(child).hex()
        address = create_address_by_pk(child_puk,prefix)
        puzzlehash = pk2_puzzle_hash(child_puk);
        PairKeys = {}
        PairKeys['index'] = i
        PairKeys['private_key'] = child_prk
        PairKeys['public_key'] = child_puk
        PairKeys['puzzlehash'] = puzzlehash
        PairKeys['address'] = address
        PairKeysDict[i] = PairKeys
        #print(f"i: {i}")
        #print(f"private_key: {private_key}")
        #print(f"public_key: {public_key}")
        #print(f"puzzlehash: {puzzlehash}")
        #print(f"address: {address}")
        
    RS['PairKeysDict'] = PairKeysDict
    
    for i in range(0, addressNumber):
        path = [12381, HDDNumber, 2, i]
        child = derive_path_unhardened(seed_key, path)
        child_puk = bytes(child.get_g1()).hex()
        child_prk = bytes(child).hex()
        address = create_address_by_pk(child_puk,prefix)
        puzzlehash = pk2_puzzle_hash(child_puk);
        PairKeys = {}
        PairKeys['index'] = i
        PairKeys['private_key'] = child_prk
        PairKeys['public_key'] = child_puk
        PairKeys['puzzlehash'] = puzzlehash
        PairKeys['address'] = address
        PairKeysDict2[i] = PairKeys
        #print(f"i: {i}")
        #print(f"private_key: {private_key}")
        #print(f"public_key: {public_key}")
        #print(f"puzzlehash: {puzzlehash}")
        #print(f"address: {address}")
    RS['PairKeysDict2'] = PairKeysDict2
        
    for i in range(0, addressNumber):
        path = [12381, HDDNumber, 5, i]
        child = derive_path(seed_key, path)
        child_puk = bytes(child.get_g1()).hex()
        child_prk = bytes(child).hex()
        address = create_address_by_pk(child_puk,prefix)
        puzzlehash = pk2_puzzle_hash(child_puk);
        PairKeys = {}
        PairKeys['index'] = i
        PairKeys['private_key'] = child_prk
        PairKeys['public_key'] = child_puk
        PairKeys['puzzlehash'] = puzzlehash
        PairKeys['address'] = address
        PairKeysDict5[i] = PairKeys
        #print(f"i: {i}")
        #print(f"private_key: {private_key}")
        #print(f"public_key: {public_key}")
        #print(f"puzzlehash: {puzzlehash}")
        #print(f"address: {address}")        
    RS['PairKeysDict5'] = PairKeysDict5

    y = json.dumps(RS)
    #hashkey = sha256(mnemonic.encode('utf-8')).hexdigest()
    #r.hset("chives_KEYS_LIST",hashkey,y)
    #print("##################################################################")
    print(y)


if __name__ == "__main__":
    create_account_and_address()