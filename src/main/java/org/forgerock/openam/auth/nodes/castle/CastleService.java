package org.forgerock.openam.auth.nodes.castle;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;
import org.forgerock.openam.sm.annotations.adapters.Password;

import java.util.List;

@Config(scope = Config.Scope.REALM)
public interface CastleService {
    /**
     * The Castle App ID
     */
    @Attribute(order = 1, requiredValue = true)
    String appId();

    /**
     * Castle CDN
     */
    @Attribute(order = 50, requiredValue = true)
    String uri();

    /**
     * The Castle API Secret
     */
    @Attribute(order = 100, requiredValue = true)
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
    List<String> denyListedHeaders();

    /**
     * Timeout
     */
    @Attribute(order = 500)
    int timeout();

    /**
     * Base URL
     */
    @Attribute(order = 700, requiredValue = true)
    default String baseURL() {
        return "https://api.castle.io/";
    }

    /**
     * Log Http Requests
     */
    @Attribute(order = 800)
    boolean logHttpRequests();
}
