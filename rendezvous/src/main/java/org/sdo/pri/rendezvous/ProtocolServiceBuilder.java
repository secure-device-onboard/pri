// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri.rendezvous;

import org.sdo.pri.ProtocolService;

@FunctionalInterface
interface ProtocolServiceBuilder {
  ProtocolService build();
}
