2.1.1 Release Notes
===============================

# Security Warning

If you downloaded the MintCoin wallet between 2018-10-28 and
2018-11-01 then you may have been infected by a virus. Please
uninstall it and run a virus scanner immediately.

We have released MintCoin 2.1.1, which has no major changes but you
can upgrade to it to make sure that you are not running an infected
version:

https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/releases/tag/v2.1.1

## Timeline

We were contacted 3 days ago (2018-11-01) because someone reported
that they discovered a virus-infected version of MintCoin downloaded
from GitHub:

https://github.com/MintcoinCommunity/Mintcoin-Desktop-Wallet/issues/100

Investigation showed that the Windows .ZIP file there had binaries
that were updated 2018-10-28 - almost 2 months after the actual
release. The Windows installer was probably also infected.

We immediately removed all binaries for version 2.1.0 from GitHub.

We contacted GitHub and asked for a history of changes to these files.
They have still not replied to our reports, so we do not know exactly
how these were modified.

We disabled access for all GitHub accounts other than EuroCentiem and
Shane Kerr. Both of us changed our GitHub passwords as well.

A new release with clean binaries, 2.1.1, was made today, 2018-11-04.

## Causes

The infected software probably had one of three sources:

1. A flaw or vulnerability in GitHub allowed someone to replace these.
   This is the least likely.

2. One of the GitHub users with access to the repository intentionally
   placed infected files there, for example to steal MintCoin,
   discredit the project, or just to break into users' computers. This
   also seems unlikely.

3. One of the GitHub users with access to the repository had their
   password guessed, or possibly was using the same password for
   GitHub on other sites and one of them was hacked. This is the most
   likely.

If we hear back from GitHub about which account modified the wallet
binaries, then we may be able to contact the user and see if they have
any more information. Unfortunately we have no contact information for
some of the old MintCoin developers so we may not be able to reach
them.

## Improvements for Future Releases

We will take steps to ensure that this sort of problem does not happen
in the future.

* Accounts for non-active developers no longer have access to the
  MintCoin community repository.
 
* The 2.1.1 release is now PGP-signed by Shane Kerr's PGP key. Users
  can use the GNU Privacy Guard to verify that the files have not been
  altered since release (Windows users may use
  [Gpg4win](https://www.gpg4win.org) for this purpose).

* We will investigate making future releases signed with a developer
  key so that Windows will check the validity automatically.