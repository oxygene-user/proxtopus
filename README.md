# imconee
Intermediate Connection Engine: socks/shadowsocks proxy client and server

The main principle of writing this project: no third-party libraries! To build the project, you will only need files from this repository.

Supported platforms: windows (can work as service), linux (not yet, but planned)<br>
Supported protocols: socks4/5 and Shadowsocks 2012 (Only AEAD cipher)<br>
For cryptography the [Botan](https://github.com/randombit/botan) library was used. However, in accordance with the main principle, the necessary files from this library were put in this repository.

