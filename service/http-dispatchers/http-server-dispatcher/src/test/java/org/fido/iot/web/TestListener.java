// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fido.iot.web;

import java.io.Closeable;
import java.io.IOException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.message.AuthException;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fido.iot.protocol.Composite;
import org.fido.iot.protocol.Const;
import org.fido.iot.protocol.CryptoService;
import org.fido.iot.protocol.InvalidJwtException;
import org.fido.iot.protocol.MessageDispatcher;
import org.fido.iot.protocol.MessagingService;
import org.fido.iot.protocol.To0ServerService;
import org.fido.iot.protocol.To0ServerStorage;

public class TestListener implements ServletContextListener {

  public static final String BEARER_TOKEN = "1234567890abcef";

  @Override
  public void contextInitialized(ServletContextEvent sce) {

    SecureRandom random = new SecureRandom();
    Provider bc = new BouncyCastleProvider();

    CryptoService cryptoService = new CryptoService();

    To0ServerStorage serverStorage = new To0ServerStorage() {
      byte[] nonce3;

      @Override
      public byte[] getNonce3() {
        return nonce3;
      }

      @Override
      public void setNonce3(byte[] nonce3) {
        this.nonce3 = nonce3;
      }

      @Override
      public long storeRedirectBlob(Composite voucher, long requestedWait, byte[] signedBlob) {
        return 60;
      }

      @Override
      public List<String> getOvKeysAllowlist() {
        List<String> allowlist = new ArrayList<>();
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
            Composite.newMap().set(Const.PI_TOKEN, TestListener.BEARER_TOKEN));
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

    To0ServerService to0Service = new To0ServerService() {
      @Override
      protected To0ServerStorage getStorage() {
        return serverStorage;
      }

      @Override
      public CryptoService getCryptoService() {
        return cryptoService;
      }
    };

    MessageDispatcher dispatcher = new MessageDispatcher() {
      @Override
      protected MessagingService getMessagingService(Composite request) {
        Composite info = request.getAsComposite(Const.SM_PROTOCOL_INFO);
        if (info.containsKey(Const.PI_TOKEN)) {
          String token = info.getAsString(Const.PI_TOKEN);
          if (!token.equals(BEARER_TOKEN)) {
            throw new InvalidJwtException(new AuthException());
          }
        }
        return to0Service;
      }

      ;
    };
    //create a message dispatcher dispatcher
    String name = sce.getServletContext().getServletContextName();
    sce.getServletContext().setAttribute(Const.DISPATCHER_ATTRIBUTE, dispatcher);
  }

  @Override
  public void contextDestroyed(ServletContextEvent sce) {

    Object obj = sce.getServletContext().getAttribute(Const.DISPATCHER_ATTRIBUTE);
    if (obj != null && obj instanceof Closeable) {
      try {
        ((Closeable) obj).close();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
