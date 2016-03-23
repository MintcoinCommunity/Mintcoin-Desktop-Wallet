// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
};

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
        vAlertPubKey = ParseHex("0447776d261ff286dc0a72b63365f1575bd9632e0ded31c58023dd5b00e8d7c1d890c914bfab3451a6d6924137f8e9dd7f1fa5e64172ee172183fd85c84a2b892f");
        nDefaultPort = 12788;
        bnProofOfWorkLimit = bnProofOfStakeLimit = ~uint256(0) >> 20;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;

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

        base58Prefixes[PUBKEY_ADDRESS] = list_of(51);  // MintCoin: address begin with 'M'
        base58Prefixes[SCRIPT_ADDRESS] = list_of(8);
        base58Prefixes[SECRET_KEY] = list_of((128 + 51));
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        // Mintcoin:
        nStakeMinAge = 60 * 60 * 24 * 20;  // minimum age for coin age: 20d
        nStakeMaxAge = 60 * 60 * 24 * 40;  // stake age of full weight: 40d
        nStakeTargetSpacing = 30;          // 30 sec block spacing

        nModifierInterval = 6 * 60 * 60;//MODIFIER_INTERVAL;
        nCoinbaseMaturity = 30;




        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
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

        vAlertPubKey = ParseHex("0471dc165db490094d35cde15b1f5d755fa6ad6f2b5ed0f340e3f17f57389c3c2af113a8cbcc885bde73305a553b5640c83021128008ddf882e856336269080496");
        nDefaultPort = 22788;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;

        // TestNet alerts private key
        // "308201130201010420b665cff1884e53da26376fd1b433812c9a5a8a4d5221533b15b9629789bb7e42a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a1440342000471dc165db490094d35cde15b1f5d755fa6ad6f2b5ed0f340e3f17f57389c3c2af113a8cbcc885bde73305a553b5640c83021128008ddf882e856336269080496"

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        //genesis.nTime = 1296688602;
        //genesis.nNonce = 414098458;
        hashGenesisBlock = /*genesis.GetHash();
        assert(hashGenesisBlock ==*/ uint256("0xaf4ac34e7ef10a08fe2ba692eb9a9c08cf7e89fcf352f9ea6f0fd73ba3e5d03c")/*)*/;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org"));
        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultCheckMemPool = false;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        // Mintcoin:
        //bnProofOfStakeLimit; // 0x00000fff PoS base target is fixed in testnet
        //bnProofOfWorkLimit; // 0x0000ffff PoW base target is fixed in testnet
        nStakeMinAge = 20 * 60; // test net min age is 20 min
        nStakeMaxAge = 60 * 60; // test net max age is 60 min
        nModifierInterval = 60; // test modifier interval is 2 minutes
        nCoinbaseMaturity = 10; // test maturity is 10 blocks
        nStakeTargetSpacing = 3 * 60; // test block spacing is 3 minutes


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
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        assert(hashGenesisBlock == uint256("0xaf4ac34e7ef10a08fe2ba692eb9a9c08cf7e89fcf352f9ea6f0fd73ba3e5d03c"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultCheckMemPool = true;
        fAllowMinDifficultyBlocks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    switch (network) {
        case CBaseChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CBaseChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CBaseChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    if (!SelectBaseParamsFromCommandLine())
        return false;

    SelectParams(BaseParams().NetworkID());
    return true;
}
