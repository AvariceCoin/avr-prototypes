from bip32utils import BIP32Key
from Crypto.Hash import RIPEMD
from termcolor import colored
from mnemonic import Mnemonic
from hashlib import sha256
import base58
import os

globj = Mnemonic("english")

wallet = ""
seedphrase = ""
public = b""
private = b""

def wallet():
  global wallet, seedphrase, public, private
  entropy = os.urandom(32)
  seedphrase = globj.to_menomic(entropy)
  seed = globj.to_seed(seedphrase, passphrase="")

  master = BIP32Key.fromEntropy(seed)
  private = master.PrivateKey()
  public = master.PublicKey()

  version = b"0x54"
  pubhash = RIPEMD.new(public)
  checksum = sha256(sha256(version + pubhash).digest()).digest()[:4]
  raw = base58.b58encode(version + pubhash + checksum).decode()

  extract = base58.b58encode(raw)
  ev = extract[0:1]
  eph = extract[1:21]
  ec = extract[21:25]
  if sha256(sha256(ev + eph + ec).digest()).digest()[:4] == checksum:
    wallet = "G" + raw + "RD"
  else:
    wallet = "INVALID"

wallet()

print(colored(f"YOUR MASTER KEY: {master.hex()}", "white", attrs=["bold"]))
print(colored(f"YOUR PRIVATE KEY: {private.hex()}", "white", attrs=["bold"]))
print(colored(f"YOUR PUBLIC KEY: {public.hex()}", "white", attrs=["bold"]))
print(colored(f"YOUR SEED PHRASE: {seedphrase}", "white", attrs=["bold"]))
print(colored(f"YOUR WALLET ADDRESS: {wallet}", "white", attrs=["bold"]))
