make DECODER_ID=0xdeadbeef
python -m remote.upload 2
sleep 3
python3 -m ectf25.utils.flash ./build/max78000.bin /dev/ttyACM2
sleep 3
python3 -m ectf25.tv.subscribe ../testsubnew.bin /dev/ttyACM2
