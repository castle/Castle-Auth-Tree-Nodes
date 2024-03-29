/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes.castle;

import com.google.common.collect.ImmutableMap;
import com.google.inject.assistedinject.Assisted;
import io.castle.client.model.CastleResponse;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;

import javax.inject.Inject;
import java.util.Map;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = CastleLogNode.Config.class, tags = {"risk"})
public class CastleLogNode extends CastleRequestNode {
    public interface Config extends CastleRequestNode.Config {
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CastleLogNode(@Assisted Config config, CoreWrapper coreWrapper,
                         AnnotatedServiceRegistry serviceRegistry, @Assisted Realm realm)
            throws NodeProcessException {
        super(config, coreWrapper, serviceRegistry, realm);
    }

    @Override
    protected CastleResponse callCastle(ImmutableMap<Object, Object> payload) {
        return castle.client().log(payload);
    }

    @Override
    protected JsonValue mapCastleResponse(CastleResponse castleResponse) {
        return JsonValue.json(null);
    }

    @Override
    protected Action nextAction(TreeContext context, JsonValue response) {
        return goToNext().build();
    }
}
