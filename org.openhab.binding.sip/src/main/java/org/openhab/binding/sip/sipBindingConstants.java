/**
 * Copyright (c) 2010-2017 by the respective copyright holders.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.sip;

import java.util.Collections;
import java.util.Set;

import org.eclipse.smarthome.core.thing.ThingTypeUID;

/**
 * The {@link sipBindingConstants} class defines common constants, which are
 * used across the whole binding.
 *
 * @author Huang - Initial contribution
 */

public class sipBindingConstants {

    private static final String BINDING_ID = "sip";

    // List of all Thing Type UIDs
    public static final ThingTypeUID THING_TYPE_REGISTAR = new ThingTypeUID(BINDING_ID, "registar");

    // List of all Channel ids
    public static final String CHANNEL_SENT = "sent";

    public static final Set<ThingTypeUID> SUPPORTED_THING_TYPES_UIDS = Collections.singleton(THING_TYPE_REGISTAR);

}
