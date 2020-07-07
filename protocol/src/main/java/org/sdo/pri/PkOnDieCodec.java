// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri;

import java.io.IOException;
import java.io.Writer;
import java.nio.CharBuffer;
import java.security.PublicKey;

class PkOnDieCodec extends Codec<PublicKey> {

  private static final String PK_NULL = "[0]";

  @Override
  Codec<PublicKey>.Decoder decoder() {
    return new Decoder();
  }

  @Override
  Codec<PublicKey>.Encoder encoder() {
    return new Encoder();
  }

  private class Decoder extends Codec<PublicKey>.Decoder {

    @Override
    public PublicKey apply(CharBuffer in) throws IOException {

      Matchers.expect(in, PK_NULL);
      return new OnDieKey(new byte[0]);
    }
  }

  private class Encoder extends Codec<PublicKey>.Encoder {

    @Override
    public void apply(Writer writer, PublicKey value) throws IOException {
      writer.write(PK_NULL);
    }
  }
}
