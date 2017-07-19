﻿using Indy.Sdk.Dotnet.Wrapper;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Indy.Sdk.Dotnet.Test.Wrapper.LedgerTests
{
    [TestClass]
    public class NodeRequestTest : IndyIntegrationTest
    {
        private Pool _pool;
        private Wallet _wallet;
        private string _walletName = "ledgerWallet";

        [TestInitialize]
        public void OpenPool()
        {
            string poolName = PoolUtils.CreatePoolLedgerConfig();
            _pool = Pool.OpenPoolLedgerAsync(poolName, null).Result;

            Wallet.CreateWalletAsync(poolName, _walletName, "default", null, null).Wait();
            _wallet = Wallet.OpenWalletAsync(_walletName, null, null).Result;
        }

        [TestCleanup]
        public void ClosePool()
        {
            _pool.CloseAsync().Wait();
            _wallet.CloseAsync().Wait();
            Wallet.DeleteWalletAsync(_walletName, null).Wait();
        }

        [TestMethod]
        public void TestBuildAttribRequestWorksForRawData()
        {
            var identifier = "Th7MpTaRZVRYnPiabds81Y";
            var dest = "Th7MpTaRZVRYnPiabds81Y";
            var data = "{\"node_ip\":\"10.0.0.100\"," +
                    "\"node_port\":910," +
                    "\"client_ip\":\"10.0.0.100\"," +
                    "\"client_port\":911," +
                    "\"alias\":\"some\"," +
                    "\"services\":[\"VALIDATOR\"]}";

            var expectedResult = string.Format("\"identifier\":\"{0}\"," +
                    "\"operation\":{{" +
                    "\"type\":\"0\"," +
                    "\"dest\":\"{1}\"," +
                    "\"data\":{2}" +
                    "}}", identifier, dest, data);

            var nodeRequest = Ledger.BuildNodeRequestAsync(identifier, dest, data).Result;

             Assert.IsTrue(nodeRequest.Replace("\\", "").Contains(expectedResult));
        }

        [TestMethod]
        public async Task TestBuildAttribRequestWorksForMissedAttribute()
        {
            var didJson = "{\"seed\":\"000000000000000000000000Steward1\"}";
            var didResult = Signus.CreateAndStoreMyDidAsync(_wallet, didJson).Result;
            var did = didResult.Did;

            var data = "{\"node_ip\":\"10.0.0.100\"," +
                    "\"node_port\":910," +
                    "\"client_ip\":\"10.0.0.100\"," +
                    "\"client_port\":910," +
                    "\"alias\":\"some\"," +
                    "\"services\":[\"VALIDATOR\"]}";

            var nodeRequest = Ledger.BuildNodeRequestAsync(did, did, data).Result;
            var ex = await Assert.ThrowsExceptionAsync<IndyException>(() => 
                Ledger.SubmitRequestAsync(_pool, nodeRequest)
            );

            Assert.AreEqual(ErrorCode.LedgerInvalidTransaction, ex.ErrorCode);
        }

        [TestMethod]
        public async Task TestBuildNodeRequestWorksForWrongServiceType()
        {
            var identifier = "Th7MpTaRZVRYnPiabds81Y";
            var dest = "Th7MpTaRZVRYnPiabds81Y";
            var data = "{\"node_ip\":\"10.0.0.100\"," +
                    "\"node_port\":910," +
                    "\"client_ip\":\"10.0.0.100\"," +
                    "\"client_port\":911," +
                    "\"alias\":\"some\"," +
                    "\"services\":[\"SERVICE\"]}";

            var ex = await Assert.ThrowsExceptionAsync<IndyException>(() =>
                Ledger.BuildNodeRequestAsync(identifier, dest, data)
            );

            Assert.AreEqual(ErrorCode.CommonInvalidStructure, ex.ErrorCode);
        }

        [TestMethod]
        public async Task TestBuildNodeRequestWorksForMissedField()
        {
            var identifier = "Th7MpTaRZVRYnPiabds81Y";
            var dest = "Th7MpTaRZVRYnPiabds81Y";
            var data = "{\"node_ip\":\"10.0.0.100\"," +
                    "\"node_port\":910," +
                    "\"client_ip\":\"10.0.0.100\"," +
                    "\"client_port\":911," +
                    "\"services\":[\"VALIDATOR\"]}";

            var ex = await Assert.ThrowsExceptionAsync<IndyException>(() =>
                Ledger.BuildNodeRequestAsync(identifier, dest, data)
            );

            Assert.AreEqual(ErrorCode.CommonInvalidStructure, ex.ErrorCode);
        }

        [TestMethod]
        public async Task TestSendNodeRequestWorksForWrongRole()
        {
            var didJson = "{\"seed\":\"000000000000000000000000Trustee1\"}";

            var didResult = Signus.CreateAndStoreMyDidAsync(_wallet, didJson).Result;
            var did = didResult.Did;

            var data = "{\"node_ip\":\"10.0.0.100\"," +
                 "\"node_port\":910," +
                 "\"client_ip\":\"10.0.0.100\"," +
                 "\"client_port\":911," +
                 "\"alias\":\"some\"," +
                 "\"services\":[\"VALIDATOR\"]}";

            var nodeRequest = Ledger.BuildNodeRequestAsync(did, did, data).Result;

            var ex = await Assert.ThrowsExceptionAsync<IndyException>(() =>
                Ledger.SignAndSubmitRequestAsync(_pool, _wallet, did, nodeRequest)
            );

            Assert.AreEqual(ErrorCode.LedgerInvalidTransaction, ex.ErrorCode);
        }

        [TestMethod]
        [Ignore]
        public void TestSendNodeRequestWorksForNewSteward()
        {
            var trusteeDidJson = "{\"seed\":\"000000000000000000000000Trustee1\"}";
            var trusteeDidResult = Signus.CreateAndStoreMyDidAsync(_wallet, trusteeDidJson).Result;
            var trusteeDid = trusteeDidResult.Did;

            var myDidJson = "{}";
            var myDidResult = Signus.CreateAndStoreMyDidAsync(_wallet, myDidJson).Result;
            var myDid = myDidResult.Did;
            var myVerkey = myDidResult.VerKey;

            var role = "STEWARD";

            var nymRequest = Ledger.BuildNymRequestAsync(trusteeDid, myDid, myVerkey, null, role).Result;
            Ledger.SignAndSubmitRequestAsync(_pool, _wallet, trusteeDid, nymRequest).Wait();

            var data = "{\"node_ip\":\"10.0.0.100\"," +
                    "\"node_port\":910," +
                    "\"client_ip\":\"10.0.0.100\"," +
                    "\"client_port\":911," +
                    "\"alias\":\"some\"," +
                    "\"services\":[\"VALIDATOR\"]}";

            var dest = "A5iWQVT3k8Zo9nXj4otmeqaUziPQPCiDqcydXkAJBk1Y";

            var nodeRequest = Ledger.BuildNodeRequestAsync(myDid, dest, data).Result;
            Ledger.SignAndSubmitRequestAsync(_pool, _wallet, myDid, nodeRequest).Wait();
        }     
    }
}
