# 2.1.1

_Bad people are bad._

This release is mostly because we had some infected binaries published
on GitHub for version 2.1.0. These were taken down as soon as they
were discovered and all accounts that could have published these were
either disabled or had their passwords updated. To help people using
the MintCoin wallet be sure that they are using a clean version, we
are releasing 2.1.1.

There are only two real changes to the code, both minor:

* We work better with the `en_DK` local, which provides ISO 8601
  formatting for dates & times.

* A few warnings for potential problems spotted by the most recent gcc
  compiler version were fixed.

# 2.1.0

_Welcome back, MintCoin!_

This is the first release of MintCoin in more than 2 years. The
primary focus has getting the code working on modern systems, as well
as fixing the most painful user issues.

* Peers updated from DNS  
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/43

  No longer will you have to give hints to the wallet so it can know
  where to connect by setting `addnode=` in your `MintCoin.conf`. An
  initial set of peers is pulled from the DNS.

  Note: We are looking for more people to run a DNS server. Scripts to
  set this up are in the
  [MintCoin-DNS-lookup-server](https://github.com/shane-kerr/MintCoin-DNS-lookup-server)
  repository.

* Fix for out-of-memory in Windows 32-bit wallet  
  Building the Qt wallet for Windows to be "large address aware" fixes
  the crashing that many Windows users experience.

  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/issues/67#issuecomment-412470755

* Display when the next coin will be available for minting as a tooltip  
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/57

  ![example tooltip](https://user-images.githubusercontent.com/1943584/38581536-b02d6eea-3cfc-11e8-8232-44e45921d4e7.png)

* Support for ARM CPU  
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/44

  The wallet can run on single-board computers (SBC) if they have
  enough RAM (about 2 gigabyte).

* Scary warnings fixed  
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/61
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/60
  https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pull/59

* Build fixes  
  We have a ton of fixes for Linux (both Debian-based and Fedora
  distributions), Windows, and macOS builds.

* Lots of other bug fixes   
  There have been quite a few other small fixes and documentation
  changes.

For a list of all of the pull requests merged, you can use the GitHub
pull requests list: 

https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/pulls?page=1&q=type%3Apr+is%3Aclosed

For a detailed set of all changes, please look at the GitHub commit
log:

https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/commits/master

Thanks to everyone who helped make this possible.
