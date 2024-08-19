# imconee
Intermediate Connection Engine: socks/shadowsocks proxy client and server

The main principle of writing this project: no third-party libraries! To build the project, you will only need files from this repository.

Supported platforms: windows (can work as service), linux<br>
Supported protocols: socks4/5 and Shadowsocks 2012 (Only AEAD cipher)<br>
For cryptography the [Botan](https://github.com/randombit/botan) library was used. However, in accordance with the main principle, the necessary files from this library were put in this repository.

# build
Source code written in c++20
To build for windows, you have to use MSVC 2022
To build for linux, you have to install at least gcc v10. You can just type make (makefile is in sources) or use Code::Blocks IDE (cbp file also included)

# install (windows)
Put **imconee64.exe** into an dir as you wish. Put **config.txt** (example included) near exe, edit it (documentation comming soon). Just run exe (as ordinary console app). To run as windows service, type **imconee64 install**.

# install (linux)
Put **config.txt** near executable file and run. More detailed instructions will be available soon.
