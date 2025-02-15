from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import deque
import struct
from typing import List, Tuple, Annotated
import json
import secrets
import hashlib
import hmac

Bytes64 = Annotated[bytes, 64]

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
) -> List[Tuple[Bytes64, str]]:
    if (begin >= 1 << depth) or (end >= 1 << depth):
        raise ValueError("The timestamps are larger than 64 bits and won't fit")
    if begin > end:
        raise ValueError("The beginning of timestamps is larger than the end")

    result = []

    queue = deque()
    queue.append((enc_left(master), "0"))
    queue.append((enc_right(master), "1"))

    while len(queue) > 0:
        key, index = queue.popleft()
        range_begin = int(index + "0" * (depth - len(index)), 2)
        range_end = int(index + "1" * (depth - len(index)), 2)

        if range_begin > end:  # out of range, too far right
            continue
        if range_end < begin:  # out of range, too far left
            continue

        # either side exceeds the range, recurse on children
        if range_begin < begin or range_end > end:
            queue.append((enc_left(key), index + "0"))
            queue.append((enc_right(key), index + "1"))
        else:  # the node is in range, take it
            result.append((key, index))

    return result


def test_cover():
    master = b"0123456789abcdef" * 2
    covers = [  # begin, end
        ["0000"],  # 0, 0
        ["000"],  # 0, 1
        ["000", "0010"],  # 0, 2
        ["00"],  # 0, 3
        ["00", "0100"],  # 0, 4
        ["00", "010"],  # 0, 5
        ["00", "010", "0110"],  # 0, 6
        ["0"],  # 0, 7
        ["0", "1000"],  # 0, 8
        ["0", "100"],  # 0, 9
        ["0", "100", "1010"],  # 0, 10
        ["0", "10"],  # 0, 11
        ["0", "10", "1100"],  # 0, 1
        ["0", "10", "110"],  # 0, 13
        ["0", "10", "110", "1110"],  # 0, 14
        ["0", "1"],  # 0, 15
    ]

    lst = []
    for end in range(16):
        lst.append([index for _, index in get_cover_wrapper(master, 0, end, 4)])

    assert lst == covers

    covers = [  # begin, end
        ["0001"],  # 1, 1
        ["0001", "0010"],  # 1, 2
        ["0001", "001"],  # 1, 3
        ["0001", "001", "0100"],  # 1, 4
        ["0001", "001", "010"],  # 1, 5
        ["0001", "001", "010", "0110"],  # 1, 6
        ["0001", "001", "01"],  # 1, 7
        ["0001", "001", "01", "1000"],  # 1, 8
        ["0001", "001", "01", "100"],  # 1, 9
        ["0001", "001", "01", "100", "1010"],  # 1, 10
        ["0001", "001", "01", "10"],  # 1, 11
        ["0001", "001", "01", "10", "1100"],  # 1, 12
        ["0001", "001", "01", "10", "110"],  # 1, 13
        ["0001", "001", "01", "10", "110", "1110"],  # 1, 14
        ["0001", "001", "01", "1"],  # 1, 15
    ]

    lst = []
    for end in range(1, 16):
        lst.append([index for _, index in get_cover_wrapper(master, 1, end, 4)])

    assert lst.sort() == covers.sort()


def get_cover(master: Bytes64, begin: int, end: int) -> List[Tuple[Bytes64, str]]:
    return get_cover_wrapper(master, begin, end, 64)


def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    global_secrets = json.loads(secrets.decode("utf-8"))
    if str(channel) not in global_secrets:
        raise ValueError("Invalid channel: No secret key found for the given channel")

    # Retrieve the master secret for the given channel
    Ks = bytes.fromhex(global_secrets[str(channel)])

    # Derive K10 = H(Ks || decoder-id) 
    K10 = hashlib.sha256(Ks + str(device_id).encode()).digest()

    # Prepare subscription structure
    #subscription_data = {
    #    "device_id": device_id,
    #    "channel": channel,
    #    "start": start,
    #    "end": end,
    #    "keys": [(key.hex(), index) for key, index in get_cover(Ks, start, end)],
    #}


    keys = get_cover(Ks, start, end)
    
    # Convert device_id and channel to fixed-length bytes (4-byte int)
    device_id_bytes = struct.pack("<I", device_id)  
    channel_bytes = struct.pack("<I", channel)  # Assuming unsigned int (4 bytes)
    
    # Convert start and end timestamps (assuming they are integers)
    start_bytes = struct.pack("<Q", start)  # Assuming 8-byte unsigned long long
    end_bytes = struct.pack("<Q", end)  # Assuming 8-byte unsigned long long

    print(keys)
    key_data = b""
    
    for key, index in keys:
        key_data += index.encode('ascii')
        key_data += b"\x00"
        key_data += key

    # Pack keys (assuming key is 16-byte and index is 4-byte int)
    # key_data = b"".join(struct.pack("64sI", key.ljust(64, b'\x00'), index) for key, index in keys)
 
    # Concatenate all parts
    subscription_data = device_id_bytes + channel_bytes + start_bytes + end_bytes + key_data

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
        global_secrets[chan_id] = secrets.token_bytes(64).hex()  # Convert bytes to hex

    global_secrets[-1] = secrets.token_bytes(64).hex()  # Convert bytes to hex

    return json.dumps(global_secrets).encode('utf-8')  # JSON serializable



    #subscription_json = json.dumps(subscription_data).encode("utf-8")

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

