# Mintcoin

Mintcoin is a community owned and operated pure Proof-of-Stake (PoS)
coin. 

Send your coins to your wallet and earn high-yielding interest for
saving your coins while securing the Mintcoin network. 

# Mintcoin Specifications

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

The Mintcoin team is on Twitter:

https://twitter.com/MintcoinTeam

There is a web-based Mintcoin block explorer:

https://mintcoin.zone/

The Telegram Mintcoin group:

https://t.me/joinchat/AYSXZBGdWRH6jeIX_EJijg

A Mintcoin fan site:

http://www.mintymintcoin.com/

# FAQ

Q: How long does it take before I can start minting?  
A: You can mint 20 days after you get Mintcoin in your wallet.

Q: What interest rate do I get?  
A: 5% annually.

Q: My wallet cannot connect to any nodes!!! What can I do?  
A: For now, you have to add some nodes by hand (sorry). You can do
   this by adding the nodes listed here:
     https://snapshot.mintcoin.zone/PEERS.txt
   To your `MintCoin.conf` file.

Q: My wallet is taking really long to synchronize. How can I speed this up?  
A: For now, you can either be patient or download a snapshot (sorry).  
   You can find a snapshot here:  
     https://snapshot.mintcoin.zone/MintCoin-Snapshot-Latest.zip  
   Stop your wallet, extract that into your Mintcoin directory, and 
   then restart your wallet. It will then start synchronizing from the
   time the last snapshot was taken.

Q: I have other questions. Are there other answers?   
A: The official FAQ can be found here:  
   https://docs.google.com/document/d/15tFqSIewTvJTZFdREVPgZgTbFGCc3VhCfM_hN9b7GaE

# Downloading the Mintcoin Wallet

The first way to get the wallet is to download binaries from the
GitHub releases link:

https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/releases

If you want pre-release binaries, they may be available on this site:

https://snapshot.mintcoin.zone/

# Building the Mintcoin Wallet

There are two separate flavors of Mintcoin wallet:

* Graphical version (a.k.a. `MintCoin-Qt`)
* Daemon version (a.k.a. `mintcoind`)

They both share much of the same code and are both in the same
repository.

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
