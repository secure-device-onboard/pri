// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fido.iot.protocol;

import java.util.List;

/**
 * To0 Server Storage Interface.
 */
public interface To0ServerStorage extends StorageEvents {

  /**
   * Gets the nonce3 value from storage.
   *
   * @return
   */
  byte[] getNonce3();

  /**
   * Sets the nonce3 value to store.
   *
   * @param nonce3 The nonce value to store.
   */
  void setNonce3(byte[] nonce3);

  /**
   * Stores the redirect blob.
   *
   * @param voucher       The ownership voucher associated with the blob.
   * @param requestedWait The requested wait time in seconds.
   * @param signedBlob    The signed blob to store.
   * @return The response wait time in seconds.
   */
  long storeRedirectBlob(Composite voucher, long requestedWait, byte[] signedBlob);

  /**
   * Gets the list of OV key hash in allowlist.
   *
   * @return
   */
  List<String> getOvKeysAllowlist();

  /**
   * Adds public key hash to allowlist DB.
   */
  void setOvKeysAllowlist();

  /**
   * Gets the list of OV key hash in denylist.
   *
   * @return
   */
  List<String> getOvKeysDenylist();

  /**
   * Adds public key hash to allowlist DB.
   */
  void setOvKeysDenylist();
}
