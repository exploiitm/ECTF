from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import deque
import struct
from typing import List, Tuple, Annotated
from dataclasses import dataclass
import json
import secrets
import hashlib

Bytes64 = Annotated[bytes, 64]


@dataclass(init=True, repr=True)
class Cover:
    nodes: List[[int, Bytes64]]
    leaves: List[[int, Bytes64]]


def enc(input: Bytes64, key: Bytes64) -> Bytes64:
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(input)
    return bytes(a ^ b for a, b in zip(encrypted, input))


def enc_right(input: Bytes64) -> Bytes64:
    key = struct.pack(">8I", *([0xDEADBEEF] * 8))
    return enc(input, key)


def enc_left(input: bytes) -> bytes:
    key = struct.pack(">8I", *([0xC0D3D00D] * 8))
    return enc(input, key)


def get_cover_wrapper(
    master: Bytes64, begin: int, end: int, depth: int
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


def get_cover(master: Bytes64, begin: int, end: int) -> Cover:
    return get_cover_wrapper(master, begin, end, 64)


def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    global_secrets = json.loads(secrets.decode("utf-8"))
    if str(channel) not in global_secrets:
        raise ValueError(
            "Invalid channel: No secret key found for the given channel")

    # Retrieve the master secret for the given channel
    Ks = bytes.fromhex(global_secrets[str(channel)])

    # Derive K10 = H(Ks || decoder-id)
    K10 = hashlib.sha256(Ks + str(device_id).encode()).digest()

    # Prepare subscription structure
    # subscription_data = {
    #    "device_id": device_id,
    #    "channel": channel,
    #    "start": start,
    #    "end": end,
    #    "keys": [(key.hex(), index) for key, index in get_cover(Ks, start, end)],
    # }

    keys = get_cover(Ks, start, end)

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
        key_data += b"\x00"
        key_data += key

    key_data += struct.pack("<Q", len(keys.leaves))
    for index, key in keys.leaves:
        key_data += struct.pack("<Q", index)
        key_data += b"\x00"
        key_data += key

    # Pack keys (assuming key is 16-byte and index is 4-byte int)
    # key_data = b"".join(struct.pack("64sI", key.ljust(64, b'\x00'), index) for key, index in keys)

    # Concatenate all parts
    subscription_data = device_id_bytes + \
        channel_bytes + start_bytes + end_bytes + key_data

    # Encode subscription data
    print(subscription_data)
    cipher = AES.new(K10, AES.MODE_ECB)
    padded_data = pad(subscription_data, AES.block_size)
    subscription_data_encrypted = cipher.encrypt(padded_data)

    # we write to sub.bin
    with open("sub.bin", "wb") as f:
        f.write(subscription_data_encrypted)  # Append the subscription data
    return subscription_data  # Returning for verification if needed


def gen_secrets(channels: list[int]) -> bytes:
    global_secrets = {}
    for chan_id in channels:
        global_secrets[chan_id] = secrets.token_bytes(
            64).hex()  # Convert bytes to hex

    global_secrets[-1] = secrets.token_bytes(64).hex()  # Convert bytes to hex

    return json.dumps(global_secrets).encode('utf-8')  # JSON serializable

    # subscription_json = json.dumps(subscription_data).encode("utf-8")


if __name__ == "__main__":
    test_cover()
    # Generate secrets for channels 1, 2, and 3 (modify as needed)
    channels = [1, 2, 3]
    secrets_data = gen_secrets(channels)

    # Define device ID and time range
    device_id = 1234
    start_time = 0
    end_time = 15
    channel = 1  # Use a valid channel

    # Generate subscription and write to sub.bin
    gen_subscription(secrets_data, device_id, start_time, end_time, channel)

    print("sub.bin has been successfully created!")
