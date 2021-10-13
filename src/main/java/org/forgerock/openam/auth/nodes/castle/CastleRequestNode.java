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
import com.google.gson.Gson;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import io.castle.client.Castle;
import io.castle.client.internal.backend.CastleBackendProvider;
import io.castle.client.model.*;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.nodes.castle.CastleHelper.CASTLE_RESPONSE;

public abstract class CastleRequestNode extends SingleOutcomeNode {

    protected final Logger logger = LoggerFactory.getLogger("amAuth");
    protected final Config config;
    protected final Castle castle;
    protected final CoreWrapper coreWrapper;
    protected final Gson gson;

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
            return AuthenticateAction.CHALLENGE;
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
     * Create the node. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    public CastleRequestNode(Config config, CoreWrapper coreWrapper)
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

        ImmutableMap<Object, Object> payload = buildPayload(context);

        try {
            logger.debug("Calling Castle API");
            CastleResponse response = callCastle(payload);

            return nextAction(context, response);
        } catch(CastleServerErrorException e) {
            logger.error("Failure when calling Castle API. Code: " + e.getResponseCode() + ". " + e.getClass());
            logger.error(e.getStackTrace().toString());
            throw new NodeProcessException(e);
        }
    }

    /**
     * Returns a next action based on the current state and the Castle Response.
     *
     */
    protected Action nextAction(TreeContext context, CastleResponse response) {
        return goToNext().replaceSharedState(context.sharedState.put(CASTLE_RESPONSE, JsonValue
                .json(gson.fromJson(response.json().getAsJsonObject(), Map.class)))).build();
    }

    /**
     * Abstract method that calls the Castle API. Override it in a subclass.
     */
    protected abstract CastleResponse callCastle(ImmutableMap<Object, Object> payload) throws NodeProcessException;

    /**
     * Builds a request payload for Castle API.
     */
    protected ImmutableMap<Object, Object> buildPayload(TreeContext context) {
        logger.debug("Building Castle payload");
        CastleContext castleContext = castle.contextBuilder().fromHttpServletRequest(context.request.servletRequest).ip(
                context.request.clientIp).build();
        String request_token = context.sharedState.get(CastleHelper.REQUEST_TOKEN).asString();
        String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();

        ImmutableMap.Builder<Object, Object> userBuild = ImmutableMap.builder().put(SharedStateConstants.USERNAME,
                username);

        String realm = context.sharedState.get(REALM).asString();
        AMIdentity userIdentity = IdUtils.getIdentity(username, realm, coreWrapper.getUserAliasList(realm));

        if (userIdentity != null) {
            try {
                userBuild.put(Castle.KEY_EMAIL, userIdentity.getAttribute(config.mailAttribute()).iterator().next());
                // context.universalId is not present in the registration flow, but once an identity is created
                // we can fetch the universalId from it
                userBuild.put("id", userIdentity.getUniversalId());
            } catch (IdRepoException | SSOException e) {
                logger.error("Unable to add user email to the request", e);
            }
        } else {
            context.universalId.ifPresent(s -> userBuild.put("id", s));
            // TODO: should this be more configurable?
            String emailFromParams =
                    context.sharedState.get(new JsonPointer("/objectAttributes/"+config.mailAttribute())).asString();
            userBuild.put(Castle.KEY_EMAIL, emailFromParams);
        }

        return ImmutableMap.builder()
                .put(Castle.KEY_EVENT, config.event().toString())
                .put(Castle.KEY_STATUS, config.status().toString())
                .put(Castle.KEY_CONTEXT,
                        ImmutableMap.builder()
                                .put(Castle.KEY_IP, castleContext.getIp())
                                .put(Castle.KEY_HEADERS, castleContext.getHeaders())
                                .build())
                .put(Castle.KEY_USER, userBuild.build())
                .put(Castle.KEY_REQUEST_TOKEN, request_token)
                .build();
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
