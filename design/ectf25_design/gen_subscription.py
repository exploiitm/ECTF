from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from collections import deque
import struct
from typing import List, Tuple, Annotated
from dataclasses import dataclass
import json
import secrets
import hmac
import hashlib
import argparse
from loguru import logger
from pathlib import Path

from nacl.signing import SigningKey

Bytes32 = Annotated[bytes, 32]


@dataclass(init=True, repr=True)
class Cover:
    nodes: List[[int, Bytes32]]
    leaves: List[[int, Bytes32]]


def enc(input: Bytes32, key: Bytes32) -> Bytes32:
    hasher = hashlib.sha3_256()
    hasher.update(key)
    hasher.update(input)
    return hasher.digest()


def enc_right(input: Bytes32) -> Bytes32:
    key = struct.pack("<8I", *([0xDEADBEEF] * 8))
    return enc(input, key)


def enc_left(input: Bytes32) -> Bytes32:
    key = struct.pack("<8I", *([0xC0D3D00D] * 8))
    return enc(input, key)


def get_cover_wrapper(
    master: Bytes32, begin: int, end: int, depth: int
) -> Cover:
    if (begin >= 1 << depth) or (end >= 1 << depth):
        raise ValueError(
            "The timestamps are larger than 64 bits and won't fit")
    if begin > end:
        raise ValueError("The beginning of timestamps is larger than the end")

    nodes = []
    leaves = []

    queue = deque()
    queue.append((1, master))

    while len(queue) > 0:
        index, key = queue.popleft()
        len_ind = len(bin(index)) - 2  # because bin() adds `0b`

        range_begin = ((index ^ (1 << (len_ind - 1)))  # remove the leading 1
                       # put it at the left of the long:
                       << (depth + 1 - len_ind))
        range_end = range_begin + \
            (1 << (depth + 1 - len_ind)) - 1  # add a bunch of 1s

        if range_begin > end:  # out of range, too far right
            continue
        if range_end < begin:  # out of range, too far left
            continue

        # either side exceeds the range, recurse on children
        if range_begin < begin or range_end > end:
            queue.append((2 * index, enc_left(key)))
            queue.append((2 * index + 1, enc_right(key)))
        else:  # the node is in range, take it
            if range_begin == range_end:
                leaves.append((index & ((1 << depth) - 1), key))
            else:
                nodes.append((index, key))

    return Cover(nodes, leaves)


def test_cover():
    master = b"0123456789abcdef" * 2
    tests = [
        [[0, 1, 1], [[1], []]],
        [[0, 1, 2], [[0b10], []]],
        [[2, 3, 2], [[0b11], []]],
        [[1, 7, 3], [[0b11, 0b101], [1]]],
        [[0, 0xFFFFFFFFFFFFFFFF, 64], [[1], []]],
        [[1, 0xFF, 8], [[0x81, 0x41, 0x21, 0x11, 0x9, 0x5, 0x3], [1]]],
    ]
    for args, res in tests:
        cover = get_cover_wrapper(master, *args)
        nodes = [node[0] for node in cover.nodes]
        leaves = [leaf[0] for leaf in cover.leaves]
        res[0].sort()
        res[1].sort()
        nodes.sort()
        leaves.sort()
        assert res[0] == nodes
        assert res[1] == leaves
    print("test_cover passed.")


def get_cover(master: Bytes32, begin: int, end: int) -> Cover:

    return get_cover_wrapper(master, begin, end, 64)


def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    assert channel != 0, "Channel 0 (Emergency Broadcast) is implicitly subscribed to."

    global_secrets = json.loads(secrets.decode("utf-8"))
    if ("K"+str(channel)) not in global_secrets:
        raise ValueError(
            "Invalid channel: No secret key found for the given channel")

    # Retrieve the master secret for the given channel
    Ks = bytes.fromhex(global_secrets["Ks"])

    hasher = hashlib.sha3_256()
    hasher.update(Ks)
    print("DEVICE IDDDD", str(device_id))
    hasher.update(str(device_id).encode())
    # Derive K10 = H(Ks || decoder-id)
    K10 = hasher.digest()
    print("Final Key Looks Like this", list(K10))

    # Prepare subscription structure
    # subscription_data = {
    #    "device_id": device_id,
    #    "channel": channel,
    #    "start": start,
    #    "end": end,
    #    "keys": [(key.hex(), index) for key, index in get_cover(Ks, start, end)],
    # }

    Kchannel = bytes.fromhex(global_secrets["K" + str(channel)])
    keys = get_cover(Kchannel, start, end)

    # Convert device_id and channel to fixed-length bytes (4-byte int)
    device_id_bytes = struct.pack("<I", device_id)
    # Assuming unsigned int (4 bytes)
    channel_bytes = struct.pack("<I", channel)

    # Convert start and end timestamps (assuming they are integers)
    # Assuming 8-byte unsigned long long
    start_bytes = struct.pack("<Q", start)
    end_bytes = struct.pack("<Q", end)  # Assuming 8-byte unsigned long long

    print("cover: ", keys)
    key_data = b""
    key_data += struct.pack("<Q", len(keys.nodes))

    for index, key in keys.nodes:
        key_data += struct.pack("<Q", index)
        key_data += key

    for index, key in keys.leaves:
        key_data += struct.pack("<Q", index)
        key_data += key

    # Pack keys (assuming key is 16-byte and index is 4-byte int)
    # key_data = b"".join(struct.pack("64sI", key.ljust(64, b'\x00'), index) for key, index in keys)

    # Concatenate all parts
    subscription_data = device_id_bytes + \
        channel_bytes + start_bytes + end_bytes + key_data

    length = len(subscription_data)
    print("CHECK THE LENGTH: ", length)
    length_bytes = struct.pack("<Q", length)
    subscription_data = length_bytes + subscription_data
    print(subscription_data)

    # Encode subscription data
    iv = get_random_bytes(16)
    cipher = AES.new(K10, AES.MODE_CBC, iv)
    pad_length = AES.block_size - (len(subscription_data) % AES.block_size)
    print("CHECK THE PAD LENGTH: ", pad_length)
    padded_data = subscription_data + b'\0' * pad_length
    subscription_data_encrypted = cipher.encrypt(padded_data)
    # # we write to sub.bin
    # with open("sub.bin", "wb") as f:
    #     f.write(subscription_data_encrypted)  # Append the subscription data
    print("This is the IV: ", iv.hex().encode())
    print("CHECK THE TOTAL LENGTH: ", len(
        iv) + len(subscription_data_encrypted))

    mac = hmac.new(K10, iv + subscription_data_encrypted,
                   hashlib.sha3_256).digest()
    
    private_key = SigningKey(bytes.fromhex(global_secrets["Kpr"]))
    sign = private_key.sign(iv + subscription_data_encrypted + mac).signature
    
    # Returning for verification if needed
    print(f"here is length{len(iv+subscription_data_encrypted + mac + sign)}")
    return iv+subscription_data_encrypted + mac + sign


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path,
                        help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # Print the generated subscription for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated subscription: {subscription}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote subscription to {
                   str(args.subscription_file.absolute())}")


def visualize_cover(l: int, r: int):
    c = (get_cover(b"0" * 32, l, r))
    nodes = []
    for n, _ in c.nodes:
        bn = bin(n)[2:]
        ntrunc = n ^ (1 << (len(bn) - 1))
        nodes.append(bin(ntrunc)[2:].rjust(len(bn) - 1) + "x" * (65 - len(bn)))
    if len(c.leaves) > 0:
        print(bin(c.leaves[0][0])[2:].rjust(64))
    print("\n".join(sorted(nodes)))
    if len(c.leaves) > 1:
        print(bin(c.leaves[1][0])[2:].rjust(64))


if __name__ == "__main__":
    main()
