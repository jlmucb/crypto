#
./pwutil.exe --operation=from-text --input=xx --output=pwout_proto
./pwutil.exe --operation=to-text --input=pwout_proto --output=pwout_txt

./pwutil.exe --operation=wrap --key=cbcschemefile1 --input=pwout_proto --output=pw_out_enc
./pwutil.exe --operation=unwrap --key=cbcschemefile1 --input=pw_out_enc --output=pwout_proto_dec
