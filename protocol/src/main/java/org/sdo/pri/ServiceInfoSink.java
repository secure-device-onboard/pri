// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.sdo.pri;

import java.util.Map.Entry;

/**
 * Consumes received ServiceInfo data.
 *
 * <p>For details on usage, see {@link ServiceInfoSource}.
 *
 * @see ServiceInfoSource
 */
@FunctionalInterface
public interface ServiceInfoSink extends ServiceInfoModule {

  void putServiceInfo(Entry<CharSequence, CharSequence> entry);
}
