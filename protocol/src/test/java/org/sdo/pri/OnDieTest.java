// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class OnDieTest {

  OnDieCache onDieCache = null;

  String b64TestSignature =
          "ARDiywa9EaMjQZ0dNWO4CbxGEL0vujai1k2rk5D/baL+8xwBsQ4ZF/eL0V/yxtaafl11BJZ7rjnesm"
        + "/H8i6Hq3r8DeObqqGDo88mVnibvb9z3zlYlLahzLkwkhxsoTRRzXIQ6km2Dm6hQX5zmRkUDiFtzadw"
        + "MDfh+dPVQMlf/vNG1j5K";
  String serialNo = "daltest";
  String b64DeviceCert =
          "MIIBszCCATqgAwIBAgIQcYhLQDPbPylyGiZ0lFRLwzAKBggqhkjOPQQDAzAeMRwwGgYDVQQDDBNDU0"
        + "1FIFRHTCBEQUxfSTAxU0RFMB4XDTE5MDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowFzEVMBMGA1UE"
        + "AwwMREFMIEludGVsIFRBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE044GJ2MiK44UHXubptTvkGefiy"
        + "rKO9ofn5v1yBVJcwpbYYTBjop/W01f7Gv7se7sMin8D1zfoEIQuahlijcsVWlG0CcB6LodLkxQi+IS"
        + "D8MNbObYIt8EGIacVVOgPdSho0QwQjAfBgNVHSMEGDAWgBSuPjAqQWKsFmeOf7U8OWyMbE+tfTAPBg"
        + "NVHRMBAf8EBTADAQEAMA4GA1UdDwEB/wQEAwIDyDAKBggqhkjOPQQDAwNnADBkAjAdss2kczBguN6s"
        + "iidupV+ipN8bCVAYe3eZV7c3i9rhTpHipVdII1/ppdswzl2IXQ0CMHNeOFuvHe64S9m2JRbBXUSdJ7"
        + "iNQwp/4+OdQUmWYs2mB7KqZpmDPGQkq5mDuygBaA==";


  OnDieCache getTestOnDieCache() throws Exception {
    if (onDieCache == null) {
      onDieCache = new OnDieCache(
              getClass().getClassLoader().getResource("cachedir").getFile(),
              false,
              null);
    }
    return onDieCache;
  }


  PublicKey getPublicKey() throws CertificateException {
    // get public key from cert path
    byte [] certBytes = Base64.getDecoder().decode(b64DeviceCert);
    CertificateFactory certificateFactory =
            CertificateFactory.getInstance("X.509", BouncyCastleLoader.load());
    Certificate cert = certificateFactory.generateCertificate(
            new ByteArrayInputStream(certBytes));
    return cert.getPublicKey();
  }

  // The following test is left disabled since it can fail depending on
  // the test environment. The test requires access to the source URLs for
  // OnDie certs and CRLs. If this test is run on a network with access then
  // it will fail. We cannot guarantee that this will be true for all environments.
  // Comment out the @Disabled if you want to run the test.
  @Test
  @DisplayName("OnDie cache download test")
  @Disabled
  void testOnDieCacheDownload(@TempDir Path tempDir) throws Exception {

    try {
      String sourceList = "https://tsci.intel.com/content/OnDieCA/certs/"
        + "https://tsci.intel.com/content/OnDieCA/crls/";

      OnDieCache onDieCache = new OnDieCache(
              tempDir.toString(),
              true,
              sourceList);

      assertNotNull(onDieCache.getCrl(
        "https://pre1-tsci.intel.com/content/OD/certs/TGL_00001846_OnDie_CA.crl"));
      assertNull(onDieCache.getCrl(
        "https://pre1-tsci.intel.com/content/OD/certs/NOT_IN_THE_CACHE.crl"));
      assertThrows(MalformedURLException.class,
        () -> onDieCache.getCrl("TGL_00001846_OnDie_CA.crl"));
    } catch (Exception ex) {
      throw ex;
    } finally {
    }
  }

  @Test
  @DisplayName("OnDie cache load test")
  void testOnDieCacheLoad() throws Exception {
    OnDieCache onDieCache = getTestOnDieCache();

    assertNotNull(onDieCache.getCrl(
      "https://pre1-tsci.intel.com/content/OD/certs/TGL_00001846_OnDie_CA.crl"));
    assertThrows(MalformedURLException.class,
      () -> onDieCache.getCrl("TGL_00001846_OnDie_CA.crl"));
  }

  @Test
  @DisplayName("OnDie invalid signed data test")
  void testOnDieSignatureInvalidSignedData() throws Exception {

    OnDieCache onDieCache = getTestOnDieCache();

    // modify the signed data and verify signature fails
    assertFalse(OnDieSignatureValidator.validateWithoutRevocations(
            serialNo + "extra data",
            Base64.getDecoder().decode(b64TestSignature),
            getPublicKey()));
  }

  @Test
  @DisplayName("OnDie invalid signature data test")
  void testOnDieSignatureInvalidSignatureData() throws Exception {

    OnDieCache onDieCache = getTestOnDieCache();

    // modify the signature data and verify signature fails
    assertFalse(OnDieSignatureValidator.validateWithoutRevocations(
      serialNo,
      Base64.getDecoder().decode(b64TestSignature.substring(1)),
      getPublicKey()));
  }

  @Test
  @DisplayName("OnDie signature test")
  void testOnDieSignature() throws Exception {

    OnDieCache onDieCache = getTestOnDieCache();

    assertTrue(OnDieSignatureValidator.validateWithoutRevocations(
      serialNo,
      Base64.getDecoder().decode(b64TestSignature),
      getPublicKey()));
  }

}
