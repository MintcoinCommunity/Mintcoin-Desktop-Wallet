// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin developers
// Copyright (c) 2014-2017 The MintCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (      0, hashGenesisBlockOfficial )
        (  10001, uint256("0x000000000844c716892664582ee292ff941798319df7e6ae02be2d56a384f58d"))
        ( 100001, uint256("0xca87908d6ed5cce4849bd14d28fc32681fbb8476be0440a9b684f3feb3b44428"))
        ( 200001, uint256("0xdb3bf8e7a0a3c2d0d173af8362cb7eff09691130c8a64d81d3771005311d7788"))
        ( 300001, uint256("0x322edb031ded9947a7a0fa0de1f8f4de8942b881fd31b4bcb81257ff8a83c56d"))
        ( 400001, uint256("0xb1a7c17b2aa8c4d60c61c7a40ccc21633dcf6756630a3cd3862dcd3b7adfc471"))
        ( 500001, uint256("0x0cb1f2a979f8c24657192a88bfa354d65f46a8dd00417085cb7ead8a2d2aea8f"))
        ( 600001, uint256("0x82b9e675bdf8d80176e9abdb4044047438e26a68a49fdf99897e18c6c9e44088"))
        ( 700001, uint256("0x0a20cd4b3093e94d7c4dfe1abfd2e83cc273b97adc5e70aa29547b6a37ed5036"))
        ( 800001, uint256("0x803466dda3dee3424b893e263255790ca0957cda8688ad2e60c8eeb83f322a36"))
        ( 900001, uint256("0x315321ae95bf68ffd993c916117b832496e26b938cd50bae042d05696ee1e779"))
        (1000001, uint256("0x02a0cb9a340a91e1c3341c605634e6b1e4488b0442b3ed56885abd9439b7cdb0"))
        (1100001, uint256("0x39cce861debcd4dd14c1629f34269b619d8d6270302141b293c25f646b92281d"))
        (1200001, uint256("0xe29429c36625832a7c0330233a25c51a00ada3b6ca0d9aa476ccbce5c284b69b"))
        (1300001, uint256("0xe2df0c7f58de124f00480fb0319a59b0e721572c9cd7d931472099c7c96b8295"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1425954579, // * UNIX timestamp of last checkpoint block
        34560886,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        10000.0     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, hashGenesisBlockTestNet )
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1425954579,
        16341,
        300
    };
/*
static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };
*/
class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xd5;
        pchMessageStart[2] = 0xdb;
        pchMessageStart[3] = 0xfa;
        vAlertPubKey = ParseHex("049c84f948ad38e6661189427b94c85721b6f2bcca6c8ce57100d1a2c934bac0cebd3c2a2bf325272dff201e2a8677f16a0f4c3b08087ef61c2ab520d9c0495c5b");
        nDefaultPort = 12788;
        bnProofOfWorkLimit = bnProofOfStakeLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 20160;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;

        // Mintcoin:
        nStakeMinAge = 60 * 60 * 24 * 20;  // minimum age for coin age: 20d
        nStakeMaxAge = 60 * 60 * 24 * 40;  // stake age of full weight: 40d
        nStakeTargetSpacing = 30;          // 30 sec block spacing

        nModifierInterval = 6 * 60 * 60;//MODIFIER_INTERVAL;
        nCoinbaseMaturity = 30;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        const char* pszTimestamp = "Feb 2, 2014: The Denver Broncos finally got on the board with a touchdown in the final seconds of the third quarter. But the Seattle Seahawks are dominating the Broncos 36-8";
        CMutableTransaction txNew;
        txNew.nTime = 1391393673;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1391393693;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 12488421;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0xaf4ac34e7ef10a08fe2ba692eb9a9c08cf7e89fcf352f9ea6f0fd73ba3e5d03c"));
        assert(genesis.hashMerkleRoot == uint256("cf174ca43b1b30e9a27f7fdc20ff9caf626499d023f1f033198fdbadf73ca747"));

        vSeeds.push_back(CDNSSeedData("seed.mintcoinofficial.com", "seed.mintcoinofficial.com"));
        vSeeds.push_back(CDNSSeedData("mintseed.mintcoinfund.org", "mintseed.mintcoinfund.org"));
        vSeeds.push_back(CDNSSeedData("mintseed.keremhd.name.tr", "mintseed.keremhd.name.tr"));
        vSeeds.push_back(CDNSSeedData("mint.seed.fuzzbawls.pw", "mint.seed.fuzzbawls.pw"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(51);  // MintCoin: address begin with 'M'
        base58Prefixes[SCRIPT_ADDRESS] = list_of(8);
        base58Prefixes[SECRET_KEY] = list_of((128 + 51));
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

//
// Testnet (v2)
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;

        vAlertPubKey = ParseHex("04596f41dcb9eff256514c2cb8ff22e0e1d6775d7cddb6287f4965c7d7d584d49a2b7bed06bb85fc0abd0738fa021cc5a980afd133efcb32b24a61598ebffa4eba");
        nDefaultPort = 22788;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;

        // Mintcoin:
        bnProofOfWorkLimit = bnProofOfStakeLimit = ~uint256(0) >> 20;
        nStakeMinAge = 20 * 60; // test net min age is 20 min
        nStakeMaxAge = 60 * 60; // test net max age is 60 min
        nModifierInterval = 60; // test modifier interval is 2 minutes
        nCoinbaseMaturity = 10; // test maturity is 10 blocks
        nStakeTargetSpacing = 3 * 60; // test block spacing is 3 minutes

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        //genesis.nTime = 1296688602;
        //genesis.nNonce = 414098458;
        hashGenesisBlock = /*genesis.GetHash();
        assert(hashGenesisBlock ==*/ uint256("0xaf4ac34e7ef10a08fe2ba692eb9a9c08cf7e89fcf352f9ea6f0fd73ba3e5d03c")/*)*/;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("mint-test.seed.fuzzbawls.pw", "mint-test.seed.fuzzbawls.pw"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        //nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        //genesis.nTime = 1296688602;
        //genesis.nBits = 0x207fffff;
        //genesis.nNonce = 2;
        nDefaultPort = 32788;
        hashGenesisBlock = /*genesis.GetHash();
        assert(hashGenesisBlock ==*/ uint256("0xaf4ac34e7ef10a08fe2ba692eb9a9c08cf7e89fcf352f9ea6f0fd73ba3e5d03c")/*)*/;

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultCheckMemPool = true;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }/*
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }*/
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine() {
    if (!SelectBaseParamsFromCommandLine())
        return false;

    SelectParams(BaseParams().NetworkID());
    return true;
}
