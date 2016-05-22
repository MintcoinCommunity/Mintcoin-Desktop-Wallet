// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "core.h"
#include "uint256.h"
#include "util.h"

static const int64_t nTargetTimespan = 30 * 30;
const int64_t nTargetSpacingWorkMax = 3 * 30;

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake) 
{
    uint256 bnTargetLimit = Params().ProofOfWorkLimit();

    if(fProofOfStake)
    {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        bnTargetLimit = Params().ProofOfStakeLimit();
    }

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
	if(nActualSpacing < 0)
	{
		// LogPrintf(">> nActualSpacing = %d corrected to 1.\n", nActualSpacing);
		nActualSpacing = 1;
	}
	else if(nActualSpacing > nTargetTimespan)
	{
		// LogPrintf(">> nActualSpacing = %d corrected to nTargetTimespan (900).\n", nActualSpacing);
		nActualSpacing = nTargetTimespan;
	}

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64_t nTargetSpacing = fProofOfStake? Params().StakeTargetSpacing() : std::min(nTargetSpacingWorkMax, (int64_t) Params().StakeTargetSpacing() * (1 + pindexLast->nHeight - pindexPrev->nHeight));
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
	
	/*
	LogPrintf(">> Height = %d, fProofOfStake = %d, nInterval = %d, nTargetSpacing = %d, nActualSpacing = %d\n", 
		pindexPrev->nHeight, fProofOfStake, nInterval, nTargetSpacing, nActualSpacing);  
	LogPrintf(">> pindexPrev->GetBlockTime() = %d, pindexPrev->nHeight = %d, pindexPrevPrev->GetBlockTime() = %d, pindexPrevPrev->nHeight = %d\n", 
		pindexPrev->GetBlockTime(), pindexPrev->nHeight, pindexPrevPrev->GetBlockTime(), pindexPrevPrev->nHeight);  
	*/

    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    if (hash == Params().HashGenesisBlock())
            return true;
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}


// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    if (block.IsProofOfStake())
    {
        // Return trust score as usual
        uint256 trustScore = (~bnTarget / (bnTarget + 1)) + 1;
        return trustScore;
    }
    else
    {
        // Calculate work amount for block
        uint256 nPoWTrust = (Params().ProofOfWorkLimit() / (bnTarget+1));
        return nPoWTrust > 1 ? nPoWTrust : 1;
    }
}
