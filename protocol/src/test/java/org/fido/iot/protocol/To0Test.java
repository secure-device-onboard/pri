// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fido.iot.protocol;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.fido.iot.certutils.PemLoader;

public class To0Test extends BaseTemplate {

  private byte[] storedBlob;
  private Composite storedVoucher;
  private Long waitResponse;
  private byte[] storedNonce3;
  private String serverToken = guid.toString();
  private String clientToken;

  @Override
  protected void setup() throws Exception {

    super.setup();
    storedBlob = null;
    storedVoucher = voucher;
    waitResponse = null;
    clientToken = null;

    final To0ClientStorage clientStorage = new To0ClientStorage() {
      @Override
      public Composite getVoucher() {
        return voucher;
      }

      @Override
      public Composite getRedirectBlob() {
        return unsignedRedirect;
      }

      @Override
      public long getRequestWait() {
        return 0;
      }

      @Override
      public void setResponseWait(long wait) {

        waitResponse = wait;
      }

      @Override
      public PrivateKey getOwnerSigningKey(PublicKey ownerPublicKey) {
        return PemLoader.loadPrivateKey(ownerKeyPem);
      }

      @Override
      public void starting(Composite request, Composite reply) {

      }

      @Override
      public void started(Composite request, Composite reply) {
        reply.set(Const.SM_PROTOCOL_INFO,
            Composite.newMap().set(Const.PI_TOKEN, serverToken));
      }

      @Override
      public void continuing(Composite request, Composite reply) {
        Composite info = request.getAsComposite(Const.SM_PROTOCOL_INFO);
        if (info.containsKey(Const.PI_TOKEN)) {
          clientToken = info.getAsString(Const.PI_TOKEN);
        }
        reply.set(Const.SM_PROTOCOL_INFO,
            Composite.newMap().set(Const.PI_TOKEN, clientToken));
      }

      @Override
      public void continued(Composite request, Composite reply) {

      }

      @Override
      public void completed(Composite request, Composite reply) {

      }

      @Override
      public void failed(Composite request, Composite reply) {

      }
    };

    clientService = new To0ClientService() {
      @Override
      protected To0ClientStorage getStorage() {
        return clientStorage;
      }

      @Override
      public CryptoService getCryptoService() {
        return cryptoService;
      }
    };

    To0ServerStorage serverStorage = new To0ServerStorage() {
      @Override
      public byte[] getNonce3() {
        return storedNonce3;
      }

      @Override
      public void setNonce3(byte[] nonce3) {

        storedNonce3 = nonce3;
      }

      @Override
      public long storeRedirectBlob(Composite voucher, long requestedWait, byte[] signedBlob) {

        storedBlob = signedBlob;
        return 3600;
      }

      @Override
      public List<String> getOvKeysAllowlist() {
        List<String> allowlist = new ArrayList<>();
        allowlist.add("42110E8F0F3184A1A5C51868BCBFF7144D66E41D1A188103C0264D5DA8BBCF88");
        allowlist.add("707B6451B8319C28E412F847E17BB87995441AF356007A03A3A4AC7745A5223D");
        allowlist.add("25D42F0536CE584E5812AB8750E80E7464742B4B65347BEA90AD4BBC71D3FFA6");
        allowlist.add("283ADF4CCB527C19A72CFB21A9FF7B555788E6B365CEF3A26C6B876EE0FFE017");
        allowlist.add("85A481BBC2DA15EDD7301FF92BA2BB60093D5864A8207F9D78A399B32AB4CFF4");
        allowlist.add("31726603CB0751BFB926B6436369265557855744338FFC3307693E0D14D5241D");
        allowlist.add("2ED65928AD50CB8542E648B9CD5C8B4BFB76DA870C723B16464F49F5140F7098");
        allowlist.add("1DAC184C6A8BB2D00665F4CFC55B1F55AC9BFB4C899B06827C0C1990A1A0F74C");
        allowlist.add("834F83875910C8507CE935BE2F947DCF854E6554C3ACB79893ACF91220EA5D8B");
        allowlist.add("B4E95FB7062303BEB84FBB606ED75CCE99D1C4B6CC88F71E65286CAD7C74F3A5");
        return allowlist;
      }

      @Override
      public void setOvKeysAllowlist() {

      }

      @Override
      public List<String> getOvKeysDenylist() {
        List<String> denylist = new ArrayList<>();
        return denylist;
      }

      @Override
      public void setOvKeysDenylist() {

      }

      @Override
      public void starting(Composite request, Composite reply) {

      }

      @Override
      public void started(Composite request, Composite reply) {
        reply.set(Const.SM_PROTOCOL_INFO,
            Composite.newMap().set(Const.PI_TOKEN, serverToken));
      }

      @Override
      public void continuing(Composite request, Composite reply) {

      }

      @Override
      public void continued(Composite request, Composite reply) {

      }

      @Override
      public void completed(Composite request, Composite reply) {

      }

      @Override
      public void failed(Composite request, Composite reply) {

      }
    };

    serverService = new To0ServerService() {
      @Override
      public To0ServerStorage getStorage() {
        return serverStorage;
      }

      @Override
      public CryptoService getCryptoService() {
        return cryptoService;
      }
    };
  }

  @Test
  void Test() throws Exception {
    setup();
    runClient(clientService.getHelloMessage());
    assertTrue(waitResponse != null);
    assertTrue(storedBlob != null);

  }

}
