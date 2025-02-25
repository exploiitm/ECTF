import json
import struct
import os
import argparse
from typing import Annotated

from Crypto.Cipher import AES
import hashlib
import hmac

# Type annotations for byte arrays of specific sizes
Bytes64 = Annotated[bytes, 64]
Bytes32 = Annotated[bytes, 32]
Bytes4 = Annotated[bytes, 4]


def jst_hash(data, key):
    hasher = hashlib.sha3_256()
    hasher.update(key)
    hasher.update(data)
    return hasher.digest()


def hmac_sha256_hash(data: Bytes32, key: Bytes32) -> Bytes32:
    '''Default Hash Function (HMAC-SHA256)'''
    return hmac.new(key, data, hashlib.sha3_256).digest()


def aes_based_hash(input_data: Bytes32, key: Bytes32) -> Bytes32:
    '''Alternative hashing function on the Davies Meyer Algorithm using AES as base.'''
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(input_data)
    return bytes(a ^ b for a, b in zip(encrypted_data, input_data))


# Key derivation section  ---------------------------------------------------------------------------------
# Configuration Constants
ENCODER_DEPTH = 64  # Maximum depth for key derivation
# HASH_FUNCTION = hmac_sha256_hash
HASH_FUNCTION = jst_hash


def pad_to_64_bytes(data: bytes) -> Bytes64:
    '''Pads the input data to 64 bytes (zero-padded if shorter, truncated if longer)'''
    return data.ljust(64, b'\x00')[:64]


def derive_right(parent_key: Bytes32) -> Bytes32:
    '''Derives the right segment key from the parent key'''
    right_key_seed = struct.pack(
        "<8I", *([0xDEADBEEF] * 8))  # Fixed right key seed
    return HASH_FUNCTION(parent_key, right_key_seed)


def derive_left(parent_key: Bytes32) -> Bytes32:
    '''Derives the left segment key from the parent key'''
    left_key_seed = struct.pack(
        "<8I", *([0xC0D3D00D] * 8))  # Fixed left key seed
    return HASH_FUNCTION(parent_key, left_key_seed)


def derive_key(master_key: Bytes32, timestamp: int) -> Bytes32:
    '''Generates a key for a given timestamp using hierarchical derivation'''
    if not (0 <= timestamp < (1 << ENCODER_DEPTH)):
        raise ValueError("Timestamp must be in range 0 to 2^64 - 1")

    key = master_key
    for bit in format(timestamp, f'0{ENCODER_DEPTH}b'):
        key = derive_left(key) if bit == '0' else derive_right(key)

    return key

# Encoder Class section ------------------------------------------------------------------------------------


class Encoder:
    def __init__(self, secrets_file_contents: bytes):
        """
        Initializes the encoder with secrets data.

        :param secrets_file_contents: Byte contents of the secrets file
        """
        self.global_secrets = json.loads(secrets_file_contents.decode("utf-8"))

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Encodes a frame for transmission by deriving a key based on the timestamp.

        :param channel: 16-bit unsigned channel number (0 is emergency broadcast)
        :param frame: Frame data (Max: 64 bytes)
        :param timestamp: 64-bit timestamp for encoding
        :return: Encoded frame ready for transmission
        """
        if "K" + str(channel) not in self.global_secrets:
            raise ValueError(
                "Invalid channel: No secret key found for the given channel")

        # Retrieve the master key for the given channel
        master_key = bytes.fromhex(self.global_secrets["K" + str(channel)])

        # Generate a timestamp-specific key using hierarchical derivation
        timestamp_key = derive_key(master_key, timestamp)

        # Generate a unique IV
        iv = os.urandom(16)

        # Encrypt the frame using AES-ECB with the derived key
        cipher = AES.new(timestamp_key, AES.MODE_CBC, iv=iv)
        encrypted_frame = cipher.encrypt(pad_to_64_bytes(frame))

        print("Unencrypted Frame:", list(pad_to_64_bytes(frame)))
        print("Encrypted Frame:", list(encrypted_frame))
        # Construct packet header
        packet_header = (
            timestamp.to_bytes(8, 'little') +  # 64-bit timestamp
            channel.to_bytes(4, 'little') +    # 32-bit channel ID
            len(frame).to_bytes(1, 'little') +  # 8-bit frame length
            iv                              # 16-bytes initialisation vector
        )
        packet_unsigned = packet_header + encrypted_frame

        # Generate HMAC signature using the same timestamp key
        signature = hmac.new(timestamp_key, packet_unsigned,
                             hashlib.sha3_256).digest()
        print("Key:", list(timestamp_key))
        print("Data:", list(packet_unsigned))
        print("Hmac:", list(signature))

        # Return the full encoded packet (header + encrypted data + HMAC signature)
        return packet_unsigned + signature

# Test main code --------------------------------------------------------------------------------------------


def main():
    """Test script for one-shot encoding of a frame."""
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType(
        "rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64-bit timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    encoded_packet = encoder.encode(
        args.channel, args.frame.encode(), args.timestamp)

    with open("../../nigga.bin", "wb") as f:
        f.write(encoded_packet)
    print("Repr Packet:", repr(encoded_packet))
    print("Hex Packet:", encoded_packet.hex())
    print("Packet Length:", len(encoded_packet))


if __name__ == "__main__":
    main()
