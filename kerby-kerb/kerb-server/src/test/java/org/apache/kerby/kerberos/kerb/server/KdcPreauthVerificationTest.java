/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.PaEncTsEnc;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2026-57915: when preauthentication is required the
 * KDC must only treat a request as pre-authenticated if at least one preauth
 * plugin actually verified the supplied padata.
 */
public class KdcPreauthVerificationTest {
    private static final String CLIENT = "alice";
    private static final String CLIENT_PASSWORD = "alice-secret";
    private static final String PKINIT_SERVER = "pkinit-svc/localhost";
    private static final EncryptionType ETYPE = EncryptionType.AES128_CTS_HMAC_SHA1_96;

    private KdcHandler kdcHandler;
    private String realm;
    private String tgsName;
    private EncryptionKey clientKey;
    private EncryptionKey tgsKey;

    @Before
    public void setUp() throws Exception {
        KdcSetting kdcSetting = new KdcSetting(new KdcConfig(), new BackendConfig());
        realm = kdcSetting.getKdcRealm();
        assertThat(kdcSetting.getKdcConfig().isPreauthRequired()).isTrue();

        IdentityBackend backend = KdcUtil.getBackend(kdcSetting.getBackendConfig());
        List<EncryptionType> etypes = Collections.singletonList(ETYPE);

        tgsName = "krbtgt/" + realm + "@" + realm;
        KrbIdentity tgs = new KrbIdentity(tgsName);
        tgs.addKeys(EncryptionUtil.generateKeys(etypes));
        backend.addIdentity(tgs);
        tgsKey = tgs.getKey(ETYPE);

        String clientName = CLIENT + "@" + realm;
        KrbIdentity client = new KrbIdentity(clientName);
        client.addKeys(EncryptionUtil.generateKeys(clientName, CLIENT_PASSWORD, etypes));
        backend.addIdentity(client);
        clientKey = client.getKey(ETYPE);

        // A server entry whose principal realm has no PKINIT context, so that
        // PkinitPreauth.verify() returns false for it.
        KrbIdentity pkinitServer = new KrbIdentity(PKINIT_SERVER + "@" + realm);
        pkinitServer.addKeys(EncryptionUtil.generateKeys(etypes));
        backend.addIdentity(pkinitServer);
        pkinitServer.setPrincipal(new PrincipalName(PKINIT_SERVER + "@NO-PKINIT." + realm));

        KdcContext kdcContext = new KdcContext(kdcSetting);
        kdcContext.setIdentityService(backend);
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init();
        kdcContext.setPreauthHandler(preauthHandler);

        kdcHandler = new KdcHandler(kdcContext);
    }

    /**
     * Sanity check: a request carrying a valid encrypted timestamp gets a TGT
     * that is flagged as pre-authenticated.
     */
    @Test
    public void testValidEncTimestampIsAccepted() throws Exception {
        AsReq asReq = makeAsReq("krbtgt/" + realm);
        asReq.addPaData(makeEncTimestamp());

        KrbMessage reply = send(asReq);

        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
        assertThat(isPreAuthFlagSet((AsRep) reply)).isTrue();
    }

    /**
     * Unknown padata next to a valid encrypted timestamp must not prevent the
     * request from being authenticated.
     */
    @Test
    public void testValidEncTimestampWithUnknownPaDataIsAccepted() throws Exception {
        AsReq asReq = makeAsReq("krbtgt/" + realm);
        asReq.addPaData(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));
        asReq.addPaData(makeEncTimestamp());

        KrbMessage reply = send(asReq);

        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
        assertThat(isPreAuthFlagSet((AsRep) reply)).isTrue();
    }

    /**
     * Exploit: padata that no preauth plugin handles used to be accepted as
     * proof of identity, handing out a TGT without knowledge of the password.
     */
    @Test
    public void testUnknownPaDataOnlyIsRejected() throws Exception {
        AsReq asReq = makeAsReq("krbtgt/" + realm);
        asReq.addPaData(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));

        assertPreauthRequired(send(asReq));
    }

    /**
     * Exploit: the token plugin returns false for a TOKEN_CHALLENGE entry,
     * which used to be ignored.
     */
    @Test
    public void testPreauthPluginReturningFalseIsRejected() throws Exception {
        AsReq asReq = makeAsReq("krbtgt/" + realm);
        asReq.addPaData(new PaDataEntry(PaDataType.TOKEN_CHALLENGE, new byte[] {0x30, 0x00}));
        asReq.addPaData(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));

        assertPreauthRequired(send(asReq));
    }

    /**
     * Exploit: the PKINIT plugin returns false when it has no context for the
     * server realm, which used to be ignored.
     */
    @Test
    public void testPkinitVerifyReturningFalseIsRejected() throws Exception {
        AsReq asReq = makeAsReq(PKINIT_SERVER);
        asReq.addPaData(new PaDataEntry(PaDataType.PK_AS_REQ, new byte[] {0x30, 0x00}));

        assertPreauthRequired(send(asReq));
    }

    /**
     * A TGS request without any TGS_REQ (AP-REQ) padata must not be treated
     * as pre-authenticated either.
     */
    @Test
    public void testTgsRequestWithoutApReqIsRejected() throws Exception {
        TgsReq tgsReq = new TgsReq();
        fillReqBody(tgsReq, "krbtgt/" + realm);
        tgsReq.addPaData(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));

        assertPreauthRequired(send(tgsReq));
    }

    private AsReq makeAsReq(String serverName) {
        AsReq asReq = new AsReq();
        fillReqBody(asReq, serverName);
        return asReq;
    }

    private void fillReqBody(KdcReq kdcReq, String serverName) {
        KdcReqBody body = new KdcReqBody();
        body.setCname(new PrincipalName(CLIENT));
        body.setRealm(realm);
        body.setSname(new PrincipalName(serverName));
        body.setTill(new KerberosTime(System.currentTimeMillis() + 3600 * 1000L));
        body.setNonce(12345);
        body.setKdcOptions(new KdcOptions());
        body.setEtypes(Collections.singletonList(ETYPE));
        kdcReq.setReqBody(body);
    }

    private PaDataEntry makeEncTimestamp() throws Exception {
        PaEncTsEnc paTs = new PaEncTsEnc();
        paTs.setPaTimestamp(KerberosTime.now());
        EncryptedData encrypted = EncryptionUtil.seal(paTs, clientKey,
                KeyUsage.AS_REQ_PA_ENC_TS);
        return new PaDataEntry(PaDataType.ENC_TIMESTAMP, KrbCodec.encode(encrypted));
    }

    private KrbMessage send(KdcReq kdcReq) throws Exception {
        ByteBuffer request = ByteBuffer.wrap(KrbCodec.encode(kdcReq));
        ByteBuffer response = kdcHandler.handleMessage(request, false,
                InetAddress.getByName("127.0.0.1"));
        return KrbCodec.decodeMessage(response);
    }

    private boolean isPreAuthFlagSet(AsRep asRep) throws Exception {
        EncTicketPart encPart = EncryptionUtil.unseal(
                asRep.getTicket().getEncryptedEncPart(), tgsKey,
                KeyUsage.KDC_REP_TICKET, EncTicketPart.class);
        return encPart.getFlags().isFlagSet(TicketFlag.PRE_AUTH);
    }

    private void assertPreauthRequired(KrbMessage reply) {
        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.KRB_ERROR);
        assertThat(((KrbError) reply).getErrorCode())
                .isEqualTo(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
    }
}
