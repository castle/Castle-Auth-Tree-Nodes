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

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.Arrays;
import java.util.NoSuchElementException;

import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

import com.iplanet.sso.SSOException;
import com.sun.identity.sm.SMSException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = CastleProfilerNode.Config.class, tags = {"risk"})
public class CastleProfilerNode extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;
    private final CastleService castleService;

    /**
     * Configuration for the node.
     */
    public interface Config {
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CastleProfilerNode(@Assisted Config config, AnnotatedServiceRegistry serviceRegistry, @Assisted Realm realm)
            throws NodeProcessException {
        this.config = config;
        try {
            this.castleService = serviceRegistry.getRealmSingleton(CastleService.class, realm).get();
        } catch (SSOException | SMSException | NoSuchElementException e) {
            throw new NodeProcessException("Cannot initialize Castle Node because the Castle Service is not configured");
        }
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("Starting Castle Profiler Node");
        JsonValue sharedState = context.sharedState;
        if (context.getCallback(TextOutputCallback.class).isPresent() && context.getCallback(HiddenValueCallback.class)
                                                                                .isPresent()) {
            logger.debug("Request Token present");
            return goToNext().replaceSharedState(
                    sharedState.put(CastleHelper.APP_ID, castleService.appId())
                               .put(CastleHelper.REQUEST_TOKEN, context.getCallback(
                                       HiddenValueCallback.class).get().getValue())).build();
        }

        String scriptSrc = String.format("%1$s?%2$s", castleService.uri(), castleService.appId());


        logger.debug("Sending client side script");
        return send(Arrays.asList(new ScriptTextOutputCallback(String.format(CastleHelper.SCRIPT, scriptSrc)),
                                  new HiddenValueCallback("request_token"))).replaceSharedState(sharedState)
                                                                            .build();

    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(CastleHelper.APP_ID), new OutputState(CastleHelper.REQUEST_TOKEN)};
    }


}
