// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.LoggerFactory;


public abstract class OnDieSignatureValidator {

  private static final int taskInfoLength = 36;  // length of the taskinfo part of OnDie signature
  private static final int rLength = 48;  // length of the r field part of OnDie signature
  private static final int sLength = 48;  // length of the s field part of OnDie signature

  /**
   * Performs a validation of the given signature with the public key
   * extracted from the cert chain.
   *
   * @param signedData signedData
   * @param signature signature
   * @param publicKey public key to validate signature with
   * @return boolean indicating if signature is valid.
   */
  public static boolean validateWithoutRevocations(
          String signedData,
          byte[] signature,
          PublicKey publicKey) {

    byte[] adjSignature = new byte[0];
    // check minimum length (taskinfo + R + S)
    if (signature.length < (36 + 48 + 48)) {
      return false;
    }
    try {
      // first 36 bytes are always the taskInfo
      byte[] taskInfo = Arrays.copyOfRange(signature, 0, 36);

      // adjust the signed data
      // data-to-verify format is: [ task-info | nonce (optional) | data ]
      // First 36 bytes of signature is the taskinfo. This value must be prepended
      // to the signedData
      ByteArrayOutputStream adjSignedData = new ByteArrayOutputStream();
      adjSignedData.write(taskInfo);
      adjSignedData.write(signedData.getBytes());

      adjSignature = convertSignature(signature, taskInfo);

      Signature sig = Signature.getInstance("SHA384withECDSA");
      sig.initVerify(publicKey);
      sig.update(adjSignedData.toByteArray());
      return sig.verify(adjSignature);
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * Performs a validation of the given signature with the public key
   * extracted from the given cert chain.
   *
   * @param signedData signedData
   * @param signature signature
   * @param certPath certificate path (dc value from ov)
   * @param onDieCache cache that contains the CRLs
   * @return boolean indicating if signature is valid.
   * @throws CertificateException when error.
   */
  public static boolean validateWithRevocations(
          String signedData,
          byte[] signature,
          CertPath certPath,
          OnDieCache onDieCache,
          boolean revocationsEnabled) throws CertificateException {

    // Check revocations first.
    List<Certificate> certificateList = (List<Certificate>) certPath.getCertificates();

    // Check revocations first.
    if (revocationsEnabled && !checkRevocations(certificateList, onDieCache)) {
      return false;
    }

    // Now validate the signature
    // Public key comes from the cert chain in the voucher.
    if (certificateList.size() == 0) {
      throw new CertificateException("OnDieSignatureValidation: Certificate chain is empty.");
    }
    return validateWithoutRevocations(signedData, signature, certificateList.get(0).getPublicKey());
  }


  private static byte[] convertSignature(byte[] signature, byte[] taskInfo)
        throws IllegalArgumentException, IOException {
    if (taskInfo.length != taskInfoLength) {
      throw new IllegalArgumentException("taskinfo length is incorrect: " + taskInfo.length);
    }

    // Format for signature should be as follows:
    // 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
    // The b1 = length of remaining bytes,
    // b2 = length of R value (vr), b3 = length of S value (vs)
    byte[] rvalue = Arrays.copyOfRange(signature, taskInfo.length, taskInfo.length + 48);
    byte[] svalue = Arrays.copyOfRange(signature, taskInfo.length + 48, taskInfo.length + 96);

    // format signature: if upper most bit is set then prepend with a 0x00 and increase length by 1
    boolean appendZeroToR = false;
    boolean appendZeroToS = false;
    if ((rvalue[0] & 0x80) != 0) {
      appendZeroToR = true;
    }
    if ((svalue[0] & 0x80) != 0) {
      appendZeroToS = true;
    }

    ByteArrayOutputStream adjSignature = new ByteArrayOutputStream();
    adjSignature.write(0x30);
    // total length of remaining bytes
    adjSignature.write(4
            + (appendZeroToR ? rLength + 1 : rLength)
            + (appendZeroToS ? sLength + 1 : sLength));
    adjSignature.write(0x02);
    // R value
    if (appendZeroToR) {
      adjSignature.write(rLength + 1);
      adjSignature.write(0x00);
      adjSignature.write(rvalue);
    } else {
      adjSignature.write(rLength);
      adjSignature.write(rvalue);
    }
    adjSignature.write(0x02);
    // S value
    if (appendZeroToS) {
      adjSignature.write(sLength + 1);
      adjSignature.write(0x00);
      adjSignature.write(svalue);
    } else {
      adjSignature.write(sLength);
      adjSignature.write(svalue);
    }
    return adjSignature.toByteArray();
  }


  private static boolean checkRevocations(
          List<Certificate> certificateList,
          OnDieCache onDieCache) {
    // Check revocations first.
    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
      for (Certificate cert : certificateList) {
        X509Certificate x509cert = (X509Certificate) cert;
        X509CertificateHolder certHolder = new X509CertificateHolder(x509cert.getEncoded());
        CRLDistPoint cdp = CRLDistPoint.fromExtensions(certHolder.getExtensions());
        if (cdp != null) {
          DistributionPoint[] distPoints = cdp.getDistributionPoints();
          for (DistributionPoint dp : distPoints) {
            GeneralName[] generalNames =
                    GeneralNames.getInstance(dp.getDistributionPoint().getName()).getNames();
            for (GeneralName generalName : generalNames) {
              byte[] crlBytes = onDieCache.getCrl(generalName.getName().toString());

              if (crlBytes == null) {
                LoggerFactory.getLogger(OnDieSignatureValidator.class).warn(
                        "CRL not found in cache for: " + generalName.getName().toString());
                return false;
              } else {
                CRL crl = certificateFactory.generateCRL(new ByteArrayInputStream(crlBytes));
                if (crl.isRevoked(cert)) {
                  return false;
                }
              }
            }
          }
        }
      }
    } catch (IOException | CertificateException | CRLException ex) {
      return false;
    }
    return true;
  }

}

