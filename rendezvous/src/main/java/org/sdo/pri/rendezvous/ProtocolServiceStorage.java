// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri.rendezvous;

import java.io.IOException;
import java.util.UUID;

import org.sdo.pri.ProtocolService;

interface ProtocolServiceStorage {

  UUID put(ProtocolService protocolService) throws IOException;

  ProtocolService take(UUID key);
}
