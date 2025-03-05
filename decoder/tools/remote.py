import argparse
import serial, time

parser = argparse.ArgumentParser(description="Process ESP32 commands.")

parser.add_argument("action", choices=["UPLOAD", "RESET"], 
                    help="Action to perform: UPLOAD or RESET")

parser.add_argument("board", type=int, choices=[1, 2, 3], 
                    help="Board number (1, 2, or 3)")

parser.add_argument("--port", type=str, default="/dev/ttyACM0", 
                    help="Port of the ESP32 (default: /dev/ttyACM0)")

parser.add_argument("--baudrate", type=int, default=115200, 
                    help="Baudrate (default: 115200)")

parser.add_argument("-v", "--verbose", action="store_true",
                    help="Increase output verbosity")
args = parser.parse_args()

result = f"{args.action} {args.board}"

if args.verbose:
    # Print parsed arguments (optional)
    print(f"Action: {args.action}")
    print(f"Board: {args.board}")
    print(f"Port: {args.port}")
    print(f"Baudrate: {args.baudrate}")



ser = serial.Serial(args.port, args.baudrate, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1)
message = args.action + str(args.board) + "\n"
ser.write(message.encode("utf-8"))
ser.close()
