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
rep = 0

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
    return wallet
  else:
    wallet = "INVALID"

wallet()
signings = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)

def transaction():
  fromWallet = wallet
  version = b"0x54"
  toWallet = wallet()
  timestamp = str(time.time())
  amount = random.randint(1, 10000)
  fee = str(amount * (random.randint(90, 99) / 100))
  sig = signings.sign_digest(sha256(fromWallet.encode("utf-8") + toWallet.encode("utf-8") + timestamp.encode("utf-8") + amount.to_bytes(4, "big") + fee.encode("utf-8")).digest())
  txid = sha256(fromWallet.encode("utf-8") + toWallet.encode("utf-8") + timestamp.encode("utf-8") + amount.to_bytes(4, "big") + fee.encode("utf-8") + sig).digest()
  weight = len(fromWallet) + len(str(amount)) + len(toWallet) + len(timestamp) + len(amount) + len(str(fee)) + len(sig) + len(txid.hex())
  return fromWallet, toWallet, timestamp, amount, fee, sig.hex(), txid.hex(), txid, weight

def block():
  version = 1
  timestamp = str(time.time())
  height = 1
  prevHash = "0"*64
  strcap = round((1.5 * 1024**2) / transaction()[8])
  transactions = [transaction()[7] for _ in range(strcap)]
  while len(transactions) > 1:
      if len(transactions) % 2 == 1:
          transactions.append(transactions[-1])
      merklet = []
      for t in range(0, len(transactions), 2):
          merklet.append(sha256(transactions[t] + transactions[t+1]).digest())
      transactions = merklet
  merkleRoot = transactions[0]
  verifiedBy = int(public.hex(), 16)
  blockHash = sha256(sha256(str(version).encode("utf-8") + strtimestamp.encode("utf-8") + str(height).encode("utf-8") + prevHash.encode("utf-8") + merkleRoot + signature).digest()).hexdigest()
  return version, height, prevHash, timestamp, merkleRoot.hex(), verifiedBy, blockHash

def pogtransaction():
  ta = False
  fa = False
  times = False
  amount = False
  fee = False
  signature = False
  txid = False
  if transaction()[3].isdigit():
    amount = True
  if len(transaction()[6]) == 64:
    txid = True
  if len(transaction()[2]) >= 18:
    times = True
  if ((transaction()[4] / transaction()[3]) * 100) >= 90:
    fee = True
  if "G" and "RD" in transaction()[0]:
    ta = True
  if "G" and "RD" in transaction()[1]:
    fa = True
  vvk = ecdsa.VerifyingKey.from_string(
      bytes.fromhex(public.hex()),
      curve=ecdsa.SECP256k1,
      hashfunc=sha256
  )
  t = sha256(transaction()[0].encode("utf-8") + transaction()[1].encode("utf-8") + transaction()[2].encode("utf-8") + transaction()[3].to_bytes(4, "big") + transaction()[4].encode("utf-8")).digest()
  try:
    vvk.verify(bytes.fromhex(transaction()[5]), t)
    signature = True
  except ecdsa.BadSignatureError:
    signature = False
  if ta and fa and times and amount and fee and signature and txid == True:
    pogblock()
  else:
    wallet()
    block()
    pogtransaction()

def pogblock():
  ver = False
  hei = False
  times = False
  prev = False
  merkle = False
  verified = False
  block = False
  finalized = False
  if block()[0] == 1:
     ver = True
  if block()[1] == 1:
    hei = True
  if len(block()[2]) == 64:
    prev = True
  if len(block()[3]) >= 18:
    times = True
  if len(block()[4]) == 64:
    merkle = True
  if str(int(public.hex(), 16)) == block()[5]:
    verified = True
  if len(block()[6]) == 64:
    block = True
  if ver and hei and times and prev and merkle and verified and block == True:
    finalized = True
    rep += 1
