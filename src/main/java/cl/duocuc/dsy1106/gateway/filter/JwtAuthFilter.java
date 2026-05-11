package cl.duocuc.dsy1106.gateway.filter;

import cl.duocuc.dsy1106.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private final JwtUtil jwtUtil;
    private final List<String> publicPaths;

    public JwtAuthFilter(JwtUtil jwtUtil,
                         @Value("${jwt.public-paths}") List<String> publicPaths) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.publicPaths = publicPaths;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // Rutas públicas: dejar pasar sin validar
            if (isPublicPath(path)) {
                return chain.filter(exchange);
            }

            // Verificar cabecera Authorization
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Missing or malformed Authorization header for path: {}", path);
                return unauthorized(exchange);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.isValid(token)) {
                log.warn("Invalid JWT token for path: {}", path);
                return unauthorized(exchange);
            }

            // Token válido: propagar claims útiles como cabeceras internas
            Claims claims = jwtUtil.validate(token);
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", String.valueOf(claims.getSubject()))
                    .header("X-User-Roles", String.valueOf(claims.get("roles")))
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        };
    }

    private boolean isPublicPath(String path) {
        return publicPaths.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    public static class Config {
        // Sin configuración extra por ahora
    }
}
