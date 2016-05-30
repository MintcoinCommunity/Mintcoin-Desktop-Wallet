// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"

#include <stdint.h>

class CBlockIndex;
class CReserveKey;
class CScript;
class CWallet;

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, CWallet* pwallet, bool fProofOfStake = false);
/** Generate a new block, without valid proof-of-work */
CBlockTemplate* CreateNewBlock(CWallet* pwallet, const CScript& scriptPubKeyIn, CBlockIndex*& pindexPrev, bool fProofOfStake=false);
CBlockTemplate* CreateNewBlockWithKey(CWallet* pwallet, CReserveKey& reservekey, CBlockIndex*& pindexPrev, bool fProofOfStake=false);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Check mined block */
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);
void UpdateTime(CBlockHeader* block, const CBlockIndex* pindexPrev);

extern double dHashesPerSec;
extern int64_t nHPSTimerStart;

#endif // BITCOIN_MINER_H
