# MintCoin

MintCoin is a community owned and operated pure Proof-of-Stake (PoS)
coin. 

Send your coins to your wallet and earn high-yielding interest for
saving your coins while securing the MintCoin network.

# MintCoin Specifications

* Pure Proof-of-Stake
* 30 seconds block target
* Difficulty retargets every block
* PoS minimum age: 20 days
* PoS maximum age: 40 days
* PoS interest: 5% annual
* 4 confirmations for transaction
  * Fast 2 minutes confirmation time for transactions!
* 50 confirmations for minted blocks
* Ports: 12788 (connection) and 12789 (RPC)

# Community 

The MintCoin team is on Twitter:

https://twitter.com/MintCoinTeam

There is a web-based MintCoin block explorer:

https://mintcoin.zone/

The Telegram MintCoin group:

https://t.me/joinchat/AYSXZBGdWRH6jeIX_EJijg

A MintCoin fan site:

http://www.mintymintcoin.com/

# FAQ

Q: How long does it take before I can start minting?  
A: You can mint 20 days after you get MintCoin in your wallet.

Q: What interest rate do I get?  
A: 5% annually (that is, 5% per year).

Q: My wallet cannot connect to any nodes!!! What can I do?  
A: For now, you have to add some nodes by hand (sorry). You can do
   this by adding the nodes listed here:  
     https://snapshot.mintcoin.zone/PEERS.txt  
   To your `MintCoin.conf` file.

Q: My wallet is taking really long to synchronize. How can I speed this up?  
A: For now, you can either be patient or download a snapshot (sorry).  
   You can find a snapshot here:  
     https://snapshot.mintcoin.zone/MintCoin-Snapshot-Latest.zip  
   Stop your wallet, extract that into your MintCoin directory, and
   then restart your wallet. It will then start synchronizing from the
   time the last snapshot was taken.

Q: When will MintCoin get added to more exchanges?  
A: Most exchanges ask for money to get added, typically a _lot_ of Bitcoin.
   Until someone organizes an effort to collect a lot of Bitcoin for this,
   MintCoin will probably not be added to any exchanges.

Q: When will there be a MintCoin coin burn?  
A: A coin burn is used by investors to drive up the value of a crypto
   currency. Since MintCoin is a community coin, there is no group of
   investors who will do this.

Q: I have other questions. Are there other answers?   
A: The official FAQ can be found here:  
   https://docs.google.com/document/d/15tFqSIewTvJTZFdREVPgZgTbFGCc3VhCfM_hN9b7GaE

# Downloading the MintCoin Wallet

The first way to get the wallet is to download binaries from the
GitHub releases link:

https://github.com/MintCoinCommunity/MintCoin-Desktop-Wallet/releases

If you want pre-release binaries, they may be available on this site:

https://snapshot.mintcoin.zone/

# Building the MintCoin Wallet

There are two separate flavors of MintCoin wallet:

* Graphical version (a.k.a. `MintCoin-Qt`)
* Daemon version (a.k.a. `mintcoind`)

They both share much of the same code and are both in the same
repository, but they are built differently.

Directions for the graphical version are found in
[doc/readme-qt.rst](doc/readme-qt.rst).

Directions for the daemon version are found in
[doc/build-unix.txt](doc/build-unix.txt),
[doc/build-msw.txt](doc/build-msw.txt), or
[doc/build-osx.txt](doc/build-osx.txt), depending on whether you are
building for a Unix-like system, Microsoft Windows, or macOS,
respectively.

Note that documentation for building Windows or macOS versions is
out-of-date and may not work. Please let us know if you get it to
work!

# Configuring the MintCoin Wallet

By default the wallet has a file called `MintCoin.conf` which stores
the configuration. The location of this file depends on whether you
running in Linux, Windows, or macOS:

|   OS    | Default configuration file                             |
|---------|--------------------------------------------------------|
| Linux   | `~/.MintCoin/MintCoin.conf`                            |
| Windows | `%USERPROFILE%\AppData\Roaming\MintCoin\MintCoin.conf` |
| macOS   | `~/Library/Application Support/MintCoin/MintCoin.conf` |

Usually this will mean something like
`/home/someuser/.MintCoin/MintCoin.conf` for Linux,
`C:\Users\SomeUser\AppData\Roaming\MintCoin\MintCoin.conf` for Windows,
and
`/Users/SomeUser/Library/Application Support/MintCoin/MintCoin.conf`
for macOS.

(Note that there is a separate configuration file for the GUI
application, in a separate directory and called `MintCoin-Qt.conf`.
Generally that should only be updated by the configuration menus in
the GUI wallet itself.)

Each line in the configuration file looks like `option=value`, sort of
like this:

```
testnet=0
maxconnections=16
listen=1
```

You can set any value there that you can set by calling the wallet
with options on the command-line. To see a full list of possible
values to set, and a brief explaination of what they mean, use:

```
$ ./mintcoind -?
```
