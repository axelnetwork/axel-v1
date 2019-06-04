// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018-2019 The AXEL Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <limits>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
        // (0, uint256("0x01"))
        (5205, uint256("9f486738935a78d8e4a4f29316d4d04ff274b952893e752159a7f3e329d8570f"))
        (15000, uint256("7eac856a1f45097b6dbcf9c9ee9af0c807190dfe6031354dcc90d9cb95a472a0"))
        (23023, uint256("a34a206d0e7b2a814c5dac6e44f47358fe9227e5ef0123007dd67a10cb4af584"))
        (30000, uint256("926137a6fa0b90f8c559e72ab123adb622ec7018403caadb329d2d75d75b611a"))
        (38900, uint256("d7f909894fb79880a7a433ab19265e3274ba67d2d53219e1e7842aaaf70bfb6f"))
    ;

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    // 1549526523,
    // 1,
    // 1
    1559063960,
    78256,
    2000
    // 1549526525, // * UNIX timestamp of last checkpoint block
    // 0,          // * total number of transactions between genesis and last checkpoint
    //             //   (the tx=... number in the SetBestChain debug.log lines)
    // 500        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet = boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {&mapCheckpointsTestnet, 1549526525, 0, 250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest = boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {&mapCheckpointsRegtest, 1549526525, 0, 0};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x23;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0xcd;
        pchMessageStart[3] = 0xdc;

        nDefaultPort = 32322;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        bnStartWork = ~uint256(0) >> 24;

        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetSpacing = 2 * 60;  // 2 minute
        nTargetSpacingSlowLaunch = 2 * 60; // before block 100
        nPoSTargetSpacing = 60;  // 1 minute
        nMaturity = 40;
        nMasternodeCountDrift = 3;
        nMaxMoneyOut = 1000000000 * COIN;
        nStartMasternodePaymentsBlock = 500;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 500;
        nModifierUpdateBlock = std::numeric_limits<decltype(nModifierUpdateBlock)>::max();

        // https://www.newsbtc.com/2019/02/07/axel-launches-a-global-decentralized-network-harnessing-the-potential-of-masternode-technology/
        const char* pszTimestamp = "AXEL @ 7 Feb 2019: a rev0lu+iVonary new decentral1z@d & distribut@d NETVV0RK";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04fed4284f0e493cb41b389b9d262066c05edd5f524b64ea2ee6d7b8aa0658f67ff98df15895e0cae5702ab31712da0453f50e931dc1c1bc5d1eba88d09d20b5b3") << OP_CHECKSIG;
        txNew.blob = "Genesis Tx";
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1549526523; // Thu, 7 Feb 2019 08:02:03 GMT
        genesis.nBits = 504365040;
        genesis.nNonce = 0x175B33;  // 545649;

        hashGenesisBlock = genesis.GetHash();
        assert(genesis.hashMerkleRoot == uint256("67d2e8a156a26373a9b96b406d5cef6b03e39071f05b0786fd376785f096ada7"));
        assert(hashGenesisBlock == uint256("000003d2dd01c2fa11ffbaf07a20ce4f966a76ce2a209412a60ecba138d99b5e"));

        // vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("", "149.28.209.176"));    // AXEL1-MASTERNODE-001 (former AXEL2-MASTERNODE-005) - Silicon Valley
        vSeeds.push_back(CDNSSeedData("", "45.76.203.147"));     // AXEL1-MASTERNODE-002 (former AXEL2-MASTERNODE-007) - Tokyo
        vSeeds.push_back(CDNSSeedData("", "139.180.218.99"));    // AXEL1-MASTERNODE-003 (former AXEL2-MASTERNODE-008) - Singapore

        vSeeds.push_back(CDNSSeedData("", "107.191.42.4"));      // AXEL2-MASTERNODE-001 - NYC
        vSeeds.push_back(CDNSSeedData("", "208.167.245.162"));   // AXEL2-MASTERNODE-002 - NYC
        vSeeds.push_back(CDNSSeedData("", "45.63.66.19"));       // AXEL2-MASTERNODE-003 - Chicago

        vSeeds.push_back(CDNSSeedData("", "155.138.244.129"));   // AXEL3-MASTERNODE-001 (former AXEL2-MASTERNODE-004) - Dallas
        vSeeds.push_back(CDNSSeedData("", "149.248.61.27"));     // AXEL3-MASTERNODE-002 (former AXEL2-MASTERNODE-006) - Toronto
        vSeeds.push_back(CDNSSeedData("", "199.247.25.42"));     // AXEL3-MASTERNODE-003 (former AXEL2-MASTERNODE-009) - Amsterdam

        vSeeds.push_back(CDNSSeedData("", "199.247.13.192"));    // AXEL2-MASTERNODE-010 - Paris
        vSeeds.push_back(CDNSSeedData("", "217.163.29.116"));    // AXEL2-MASTERNODE-011 - Franfurt
        vSeeds.push_back(CDNSSeedData("", "209.250.229.177"));   // AXEL2-MASTERNODE-012 - London
        vSeeds.push_back(CDNSSeedData("", "45.32.241.121"));     // AXEL2-MASTERNODE-013 - Sydney
        vSeeds.push_back(CDNSSeedData("", "207.246.103.19"));    // AXEL2-MASTERNODE-014 - Los Angles

        vSeeds.push_back(CDNSSeedData("", "108.61.241.113"));    // AXEL1-MN-005 (former AXEL2-MASTERNODE-015)
        vSeeds.push_back(CDNSSeedData("", "144.202.72.110"));    // AXEL2-MN-005 (former AXEL2-MASTERNODE-016)
        vSeeds.push_back(CDNSSeedData("", "95.179.238.23"));     // AXEL3-MN-005 (former AXEL2-MASTERNODE-017)
        vSeeds.push_back(CDNSSeedData("", "139.180.223.77"));    // AXEL3-MN-006 (former AXEL2-MASTERNODE-018)

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 23); // A
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 75); // X
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 83);     // a
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md 9984
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x04)(0x61).convert_to_container<std::vector<unsigned char> >(); // 1121

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        // vFixedSeeds.clear();
        // vSeeds.clear();

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;

        vAlertPubKey = ParseHex("04732afb18c3c41a739fb00b381291d8da4e4d74606c88eb85496899ed7638911792f0a7fd0bdfa51e7587f2c006a4a16aaf475d11e0b8106dfd3f23f9e9bedf62");
        vGMPubKey = ParseHex("04fed4284f0e493cb41b389b9d262066c05edd5f524b64ea2ee6d7b8aa0658f67ff98df15895e0cae5702ab31712da0453f50e931dc1c1bc5d1eba88d09d20b5b3");
        strSporkKey = "048563419991ec5e3566a0b6fd067bd65912a491363986c4ea447662c6fe449698aca198fe0c3fbbec6da98971e77e96ac9463a85dbe4f2a30275cdeba0ac99855";
        strObfuscationPoolDummyAddress = "AMtbTau7tfT9juwVXu7Xegevqg4zu9y4M6";
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xd9;
        pchMessageStart[1] = 0x79;
        pchMessageStart[2] = 0x68;
        pchMessageStart[3] = 0xbd;

        bnProofOfWorkLimit = ~uint256(0) >> 1;
        bnStartWork = bnProofOfWorkLimit;

        nDefaultPort = 42322;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetSpacing = 1 * 60;  // 1 minute
        nLastPOWBlock = std::numeric_limits<decltype(nLastPOWBlock)>::max();
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = std::numeric_limits<decltype(nModifierUpdateBlock)>::max();
        nMaxMoneyOut = 1000000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1549526523; // Thu, 7 Feb 2019 08:02:03 GMT
        genesis.nNonce = 0;

        hashGenesisBlock = genesis.GetHash();

        // assert(hashGenesisBlock == uint256("019a701040d795514ea77eda681e74f8de73afdb1b39d541fc0c697585b878dc"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 83);   // Testnet AXEL addresses start with 'a'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 137);  // Testnet AXEL script addresses start with 'x'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 23);       // Testnet private keys start with 'A'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        //convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;

        vAlertPubKey = ParseHex("04fed4284f0e493cb41b389b9d262066c05edd5f524b64ea2ee6d7b8aa0658f67ff98df15895e0cae5702ab31712da0453f50e931dc1c1bc5d1eba88d09d20b5b3");
        vGMPubKey = ParseHex("0414b78fd29848ca55bacabe49c6bf53c8cb5224cdd84590f21616457c564b01d2c26c69fea8a55b5e336cb40981ba3167b04ddd149a21f59ab07cf30a4b7285b1");
        strSporkKey = "04d549d4d839d8c404e18f3b4c5722c471bde4df76c77a48d52ddfa07fe6d07a753d5ddba68fc6addcfda2779b3ded5d18be69fefba8c58610f1d7eb2a2ad6a3a2";
        strObfuscationPoolDummyAddress = "AMtbTau7tfT9juwVXu7Xegevqg4zu9y4M6";

    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xf8;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xaf;

        bnStartWork = ~uint256(0) >> 20;

        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetSpacing = 1 * 60;
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1549526523; // Thu, 7 Feb 2019 08:02:03 GMT
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 52322;

        //assert(hashGenesisBlock == uint256("300552a9db8b2921c3c07e5bbf8694df5099db579742e243daeaf5008b1e74de"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fMineBlocksOnDemand = true;


    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
