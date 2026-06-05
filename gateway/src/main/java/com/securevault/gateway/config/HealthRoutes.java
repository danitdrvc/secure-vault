package com.securevault.gateway.config;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * Sopstveni health endpoint gateway-a (reaktivni RouterFunction).
 * Ne ide kroz backend rutu (/health ne odgovara predikatu /api/**).
 */
@Configuration
public class HealthRoutes {

    @Bean
    public RouterFunction<ServerResponse> healthRoute() {
        return route(GET("/health"),
                request -> ServerResponse.ok().bodyValue(Map.of("status", "ok")));
    }
}
