// Copyright (c) 2012-2017 The Bitcoin developers
// Copyright (c) 2014-2017 The MintCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

//
// network protocol versioning
//

static const int PROTOCOL_VERSION = 60008;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;
static const int MIN_PEER_PROTO_VERSION_FORK = 60007;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 31800;
static const int MINT_HDF_SYNC_VERSION = 60008;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = GETHEADERS_VERSION;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! only request blocks from nodes outside this range of versions
static const int NOBLKS_VERSION_START = 60002;
static const int NOBLKS_VERSION_END = 60004;
static const int NOBLKS_VERSION_END_FORK = 60006;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
static const int MEMPOOL_GD_VERSION = 60002;

#endif // BITCOIN_VERSION_H
