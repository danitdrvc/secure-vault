package com.securevault.gateway;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.securevault.gateway.config.HealthRoutes;

class GatewayApplicationTests {

    @Test
    void healthRouteReturnsStatusOk() {
        RouterFunction<ServerResponse> routes = new HealthRoutes().healthRoute();

        WebTestClient client = WebTestClient.bindToRouterFunction(routes).build();

        client.get().uri("/health")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("ok");
    }

    @Test
    void unknownPathOnHealthRouterIsNotFound() {
        RouterFunction<ServerResponse> routes = route(GET("/health"),
                request -> ServerResponse.ok().bodyValue(Map.of("status", "ok")));

        WebTestClient client = WebTestClient.bindToRouterFunction(routes).build();

        client.get().uri("/does-not-exist")
                .exchange()
                .expectStatus().isNotFound();
    }
}
