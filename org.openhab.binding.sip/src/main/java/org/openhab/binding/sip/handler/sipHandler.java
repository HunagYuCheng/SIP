/**
 * Copyright (c) 2010-2017 by the respective copyright holders.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.sip.handler;

import org.eclipse.smarthome.config.core.Configuration;
import org.eclipse.smarthome.core.library.types.OnOffType;
import org.eclipse.smarthome.core.thing.ChannelUID;
import org.eclipse.smarthome.core.thing.Thing;
import org.eclipse.smarthome.core.thing.ThingStatus;
import org.eclipse.smarthome.core.thing.binding.BaseThingHandler;
import org.eclipse.smarthome.core.types.Command;
import org.openhab.binding.sip.shootist.shootist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link sipHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Huang - Initial contribution
 */
public class sipHandler extends BaseThingHandler {

    private final shootist connection = new shootist();

    private final Logger logger = LoggerFactory.getLogger(sipHandler.class);

    private static final String REGISTAR_PARAM = "name";

    private static String name;

    public sipHandler(Thing thing) {
        super(thing);
    }

    @Override
    public void initialize() {
        logger.info("-------------------------Initializing SipRegistar handler----------------------------");
        updateStatus(ThingStatus.ONLINE);
        Configuration config = getThing().getConfiguration();
        name = (String) config.get(REGISTAR_PARAM);
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        if (command instanceof OnOffType) {
            OnOffType s = (OnOffType) command;
            if (s == OnOffType.ON) {
                connection.init();
            }
        }
    }

    public static String getname(String n) {
        return name;
    }
}
