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

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.nodes.castle.CastleHelper.CASTLE_RESPONSE;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;

import io.castle.client.Castle;
import io.castle.client.internal.backend.CastleBackendProvider;
import io.castle.client.model.AuthenticateAction;
import io.castle.client.model.AuthenticateFailoverStrategy;
import io.castle.client.model.CastleContext;
import io.castle.client.model.CastleResponse;
import io.castle.client.model.CastleSdkConfigurationException;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = CastleRiskNode.Config.class, tags = {"risk"})
public class CastleRiskNode extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;
    private final Castle castle;
    private final CoreWrapper coreWrapper;
    private final Gson gson;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The Castle API Secret
         */
        @Attribute(order = 100)
        @Password
        char[] apiSecret();

        /**
         * Castle Event Type
         */
        @Attribute(order = 200)
        default Event event() {
            return Event.LOGIN;
        }

        /**
         * Castle Status
         */
        @Attribute(order = 250)
        default Status status() {
            return Status.SUCCEEDED;
        }

        /**
         * Allow listed headers
         */
        @Attribute(order = 300)
        List<String> allowListedHeaders();

        /**
         * Allow listed headers
         */
        @Attribute(order = 400)
        default List<String> denyListedHeaders() { return Arrays.asList("cookie"); }

        /**
         * Timeout
         */
        @Attribute(order = 500)
        default int timeout() {
            return 500;
        }

        /**
         * Failover Strategy
         */
        @Attribute(order = 600)
        default AuthenticateAction failOverStrategy() {
            return AuthenticateAction.ALLOW;
        }

        /**
         * Base URL
         */
        @Attribute(order = 700)
        default String baseURL() {
            return "https://api.castle.io/";
        }

        /**
         * Log Http Requests
         */
        @Attribute(order = 800)
        default boolean logHttpRequests() {
            return false;
        }

        /**
         * Mail Attribute
         */
        @Attribute(order = 900)
        default String mailAttribute() {
            return "mail";
        }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CastleRiskNode(@Assisted Config config, CoreWrapper coreWrapper)
            throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.gson = new Gson();
        try {
            castle = Castle.initialize(Castle.configurationBuilder().apiSecret(String.valueOf(config.apiSecret()))
                                             .withAllowListHeaders(config.allowListedHeaders()).withDenyListHeaders(
                            config.denyListedHeaders()).withTimeout(config.timeout()).withBackendProvider(
                            CastleBackendProvider.OKHTTP).withAuthenticateFailoverStrategy(
                            new AuthenticateFailoverStrategy(config.failOverStrategy())).withApiBaseUrl(
                            config.baseURL()).withLogHttpRequests(config.logHttpRequests()).build());
        } catch (CastleSdkConfigurationException e) {
            throw new NodeProcessException("Cannot initialize the castle SDK");
        }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("Starting Castle Risk Node");
        CastleContext castleContext = castle.contextBuilder().fromHttpServletRequest(context.request.servletRequest).ip(
                context.request.clientIp).build();
        String request_token = context.sharedState.get(CastleHelper.REQUEST_TOKEN).asString();
        String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();

        ImmutableMap.Builder<Object, Object> userBuild = ImmutableMap.builder().put(SharedStateConstants.USERNAME,
                                                                                    username);
        String realm = context.sharedState.get(REALM).asString();
        context.universalId.ifPresent(s -> userBuild.put("id", s));
        AMIdentity userIdentity = IdUtils.getIdentity(username, realm, coreWrapper.getUserAliasList(realm));
        try {
            userBuild.put(Castle.KEY_EMAIL, userIdentity.getAttribute(config.mailAttribute()).iterator().next());
        } catch (Exception e) {
            logger.error("Unable to add user email to the request", e);
        }
        try {
            CastleResponse response = castle.client().risk(
                    ImmutableMap.builder()
                            .put(Castle.KEY_EVENT, config.event().toString())
                            .put(Castle.KEY_STATUS, config.status().toString())
                            .put(Castle.KEY_CONTEXT,
                                    ImmutableMap.builder()
                                            .put(Castle.KEY_IP, castleContext.getIp())
                                            .put(Castle.KEY_HEADERS, castleContext.getHeaders())
                                            .build())
                            .put(Castle.KEY_USER, userBuild.build())
                            .put(Castle.KEY_REQUEST_TOKEN, request_token)
                            .build());
            logger.debug("Called Castle Risk API");
            return goToNext().replaceSharedState(context.sharedState.put(CASTLE_RESPONSE, JsonValue
                    .json(gson.fromJson(response.json().getAsJsonObject(), Map.class)))).build();
        } catch (Exception e) {
            logger.error("Failure when calling Castle API", e);
            throw new NodeProcessException(e);
        }
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(CASTLE_RESPONSE)};
    }

    /**
     * Castle Event type
     */
    public enum Event {
        LOGIN("$login"),
        REGISTRATION("$registration"),
        PROFILE_UPDATE("$profile_update"),
        TRANSACTION("$transaction"),
        PASSWORD_RESET_REQUEST("$password_reset_request");
        private final String event;

        Event(String event) {
            this.event = event;
        }

        @Override
        public String toString() {
            return event;
        }
    }

    public enum Status {
        SUCCEEDED("$succeeded"),
        FAILED("$failed"),
        ATTEMPTED("$attempted");

        private final String status;

        Status(String status) { this.status = status; }

        @Override
        public String toString() {
            return status;
        }
    }


}
