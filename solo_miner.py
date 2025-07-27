import socket
import json
import hashlib
import struct
import time

HOST = "eusolo.ckpool.org"
PORT = 3333
USERNAME = "username"  # replace with your ckpool username
PASSWORD = "x"          # ckpool often ignores the password
WORKER = "worker1"      # worker name


def sha256d(data: bytes) -> bytes:
    """Perform double SHA256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bits_to_target(bits_hex: str) -> int:
    """Convert compact bits encoding to target integer"""
    bits = int(bits_hex, 16)
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    return mantissa << (8 * (exponent - 3))


def pack_uint32_le(value: int) -> bytes:
    return struct.pack('<I', value)


def connect_stratum():
    """Connect to the Stratum server and perform subscribe/authorize"""
    s = socket.create_connection((HOST, PORT))
    f = s.makefile('r')

    def send(method, params):
        payload = json.dumps({'id': 1, 'method': method, 'params': params}) + '\n'
        s.sendall(payload.encode())

    # Subscribe
    send('mining.subscribe', [])
    sub_resp = json.loads(f.readline())
    extranonce1 = sub_resp['result'][1]
    extranonce2_size = sub_resp['result'][2]

    # Authorize
    send('mining.authorize', [f'{USERNAME}.{WORKER}', PASSWORD])
    auth_resp = json.loads(f.readline())
    if not auth_resp.get('result'):
        raise RuntimeError('Authorization failed: %s' % auth_resp)

    print('Subscribed with extranonce1', extranonce1)
    return s, f, extranonce1, extranonce2_size


def build_coinbase(coinb1, coinb2, extranonce1: str, extranonce2: bytes) -> bytes:
    return bytes.fromhex(coinb1) + bytes.fromhex(extranonce1) + extranonce2 + bytes.fromhex(coinb2)


def merkle_root(coinbase_hash: bytes, branches: list) -> bytes:
    merkle = coinbase_hash
    for b in branches:
        merkle = sha256d(merkle + bytes.fromhex(b))
    return merkle


def mine():
    s, f, extranonce1, extranonce2_size = connect_stratum()
    extranonce1_bytes = bytes.fromhex(extranonce1)
    while True:
        line = f.readline()
        if not line:
            break
        msg = json.loads(line)
        if msg.get('method') != 'mining.notify':
            continue
        params = msg['params']
        job_id = params[0]
        prev_hash = params[1]
        coinb1 = params[2]
        coinb2 = params[3]
        merkle_branch = params[4]
        version = params[5]
        bits = params[6]
        ntime = params[7]

        extranonce2 = b'\x00' * extranonce2_size
        coinbase = build_coinbase(coinb1, coinb2, extranonce1, extranonce2)
        coinbase_hash = sha256d(coinbase)
        root = merkle_root(coinbase_hash, merkle_branch)

        header = (
            bytes.fromhex(version)[::-1] +
            bytes.fromhex(prev_hash)[::-1] +
            root[::-1] +
            bytes.fromhex(ntime)[::-1] +
            bytes.fromhex(bits)[::-1] +
            b'\x00\x00\x00\x00'  # placeholder nonce
        )
        target = bits_to_target(bits)

        print('Mining on job', job_id)
        nonce = 0
        while nonce < 0xffffffff:
            block = header[:-4] + pack_uint32_le(nonce)
            hash_val = sha256d(block)
            if int.from_bytes(hash_val[::-1], 'big') < target:
                print('Found share', hex(nonce))
                submit = json.dumps({
                    'id': 1,
                    'method': 'mining.submit',
                    'params': [f'{USERNAME}.{WORKER}', job_id, extranonce2.hex(), ntime, f'{nonce:08x}']
                }) + '\n'
                s.sendall(submit.encode())
                resp = json.loads(f.readline())
                print('Submit result', resp)
                break
            nonce += 1
        else:
            print('Job changed before share found')


if __name__ == '__main__':
    try:
        mine()
    except KeyboardInterrupt:
        print('Stopping miner')
