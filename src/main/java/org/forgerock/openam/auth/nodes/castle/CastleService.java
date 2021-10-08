package org.forgerock.openam.auth.nodes.castle;

import com.google.inject.assistedinject.Assisted;
import io.castle.client.model.AuthenticateAction;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.sm.annotations.adapters.Password;

import javax.inject.Inject;
import java.util.Arrays;
import java.util.List;

@Config(scope = Config.Scope.REALM)
public interface CastleService {
    /**
     * The Castle App ID
     */
    @Attribute(order = 1)
    String appId();

    /**
     * Castle CDN
     */
    @Attribute(order = 50)
    default String uri() {
        return "https://d2t77mnxyo7adj.cloudfront.net/v1/c.js";
    }

    /**
     * The Castle API Secret
     */
    @Attribute(order = 100)
    @Password
    char[] apiSecret();

    /**
     * Allow listed headers
     */
    @Attribute(order = 300)
    List<String> allowListedHeaders();

    /**
     * Allow listed headers
     */
    @Attribute(order = 400)
    default List<String> denyListedHeaders() {
        return Arrays.asList("cookie");
    }

    /**
     * Timeout
     */
    @Attribute(order = 500)
    default int timeout() {
        return 500;
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
}
