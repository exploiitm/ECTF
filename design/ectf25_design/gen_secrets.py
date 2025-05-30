import argparse
import json
from pathlib import Path

from loguru import logger
import secrets

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """
    private_key = SigningKey.generate()

    assert 0 not in channels, "Channel 0 (Emergency Broadcast) is automatically added"

    global_secrets = {}
    for chan_id in channels:
        global_secrets["K"+str(chan_id)] = secrets.token_bytes(16).hex()

    global_secrets["K0"] = secrets.token_bytes(32).hex()
    global_secrets["Ks"] = secrets.token_bytes(32).hex()
    global_secrets["Kpr"] = private_key.encode(encoder=HexEncoder).decode()
    global_secrets["Kpu"] = private_key.verify_key.encode(encoder=HexEncoder).decode()

    return json.dumps(global_secrets).encode('utf-8')

    # NOTE: if you choose to use JSON for your file type, you will not be able to
    # store binary data, and must either use a different file type or encode the
    # binary data to hex, base64, or another type of ASCII-only encoding


def parse_args():
    """
    Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
