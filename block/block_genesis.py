from bip32utils import BIP32Key
from Crypto.Hash import RIPEMD
from termcolor import colored
from mnemonic import Mnemonic
from hashlib import sha256
import random
import base58
import ecdsa
import time
import os

globj = Mnemonic("english")

master = ""
wallet = ""
seedphrase = ""
public = b""
private = b""

def wallet():
  global wallet, seedphrase, public, private, master
  entropy = os.urandom(16)
  seedphrase = globj.to_mnemonic(entropy)
  seed = globj.to_seed(seedphrase, passphrase="")

  master = BIP32Key.fromEntropy(seed)
  private = master.PrivateKey()
  public = master.PublicKey()

  version = b"0x54"
  pubhash = RIPEMD.new(public).digest()
  checksum = sha256(sha256(version + pubhash).digest()).digest()[:4]
  raw = base58.b58encode(version + pubhash + checksum).decode()

  extract = base58.b58decode(raw)
  ev = extract[0:1]
  eph = extract[1:21]
  ec = extract[21:25]
  if sha256(sha256(ev + eph).digest()).digest()[:4] == checksum:
    wallet = "G" + raw + "RD"
  else:
    wallet = "INVALID"

wallet()
signings = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)

def transaction():
  fromWallet = wallet
  version = b"0x54"
  toWallet = "G" + base58.b58encode(sha256(os.urandom(10)).digest()).decode() + "RD"
  timestamp = str(time.time())
  amount = random.randint(1, 10000)
  fee = str(amount * (random.randint(90, 99) / 100))
  sig = signings.sign_digest(sha256(fromWallet.encode("utf-8") + toWallet.encode("utf-8") + timestamp.encode("utf-8") + amount.to_bytes(4, "big") + fee.encode("utf-8")).digest())
  txid = sha256(fromWallet.encode("utf-8") + toWallet.encode("utf-8") + timestamp.encode("utf-8") + amount.to_bytes(4, "big") + fee.encode("utf-8") + sig).digest()
  weight = len(fromWallet) + len(str(amount)) + len(toWallet) + len(timestamp) + len(amount) + len(str(fee)) + len(sig) + len(txid.hex())
  return {"from": fromWallet, "to": toWallet, "timestamp": timestamp, "amount": amount, "fee": fee, "signature": sig.hex(), "txid": txid.hex()}, txid, weight

def block():
  version = 1
  timestamp = str(time.time())
  height = 1
  prevHash = "0"*64
  strcap = round((1.5 * 1024**2) / transaction()[2])
  transactions = [transaction()[1] for _ in range(strcap)]
  while len(transactions) > 1:
      if len(transactions) % 2 == 1:
          transactions.append(transactions[-1])
      merklet = []
      for t in range(0, len(transactions), 2):
          merklet.append(sha256(transactions[t] + transactions[t+1]).digest())
      transactionz = merklet
  merkleRoot = transactionz[0]
  verifiedBy = int(public.hex(), 16)
  blockHash = sha256(sha256(str(version).encode("utf-8") + strtimestamp.encode("utf-8") + str(height).encode("utf-8") + prevHash.encode("utf-8") + merkleRoot + signature).digest()).hexdigest()
  return {"version": version, "height": height, "prevHash": prevHash, "timestamp": timestamp, "merkleRoot": merkleRoot.hex(), "verifiedBy": verifiedBy, "blockHash": blockHash}
