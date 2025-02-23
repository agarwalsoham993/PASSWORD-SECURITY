Application of hashcat in terminal 
testing of various different algorithms which could have been used in encrypting the 
password by the server.

C:\Users\agarw\Desktop\hashcat-6.2.6> hashcat -m 0 -a 0 hashtask.txt wordlists\rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #1: Intel(R) UHD Graphics, 1568/3252 MB (813 MB allocatable), 80MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 19 digests; 19 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 491 MB

Dictionary cache built:
* Filename..: wordlists\rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

d8578edf8458ce06fbc5bb76a58c5ca4:qwerty
96e79218965eb72c92a549dd5a330112:111111
7c6a180b36896a0a8c02787eeafb0e4c:password1
e10adc3949ba59abbe56e057f20f883e:123456
25f9e794323b453885f5181f1b624d0b:123456789
5f4dcc3b5aa765d61d8327deb882cf99:password
fcea920f7412b5da7be0cf42b8c93759:1234567
25d55ad283aa400af464c76d713c07ad:12345678
e99a18c428cb38d5f260853678922e03:abc123
6c569aabbf7775ef8fc570e228c16b98:password!
3f230640b78d7e71ac5514e57935eb69:qazxsw
f6a0cb102c62879d397b12b62c092c06:bluered
917eb5e9d6d6bca820922a0c6f7cc28b:Pa$$word1
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashtask.txt
Time.Started.....: Mon Feb 24 01:15:46 2025, (5 secs)
Time.Estimated...: Mon Feb 24 01:15:51 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (wordlists\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2776.6 kH/s (8.93ms) @ Accel:64 Loops:1 Thr:64 Vec:1
Recovered........: 13/19 (68.42%) Digests (total), 13/19 (68.42%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[303334323137383439] -> $HEX[042a0337c2a156616d6f732103]

Started: Mon Feb 24 01:15:41 2025
Stopped: Mon Feb 24 01:15:52 2025

C:\Users\agarw\Desktop\hashcat-6.2.6>