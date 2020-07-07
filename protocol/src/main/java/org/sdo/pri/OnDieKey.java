// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;

class OnDieKey extends EncodedKeySpec implements PublicKey, PrivateKey {

  OnDieKey(byte[] data) {
    super(data);
  }

  @Override
  public String getAlgorithm() {
    return getType().toString();
  }

  @Override
  public String getFormat() {
    return getType().toString();
  }

  KeyType getType() {
    return KeyType.DAL_ECDSA;
  }
}

