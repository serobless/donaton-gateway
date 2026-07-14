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
import java.util.stream.Collectors;

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
            String method = request.getMethod() != null ? request.getMethod().name() : "GET";

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (isPublicPath(path)) {
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);
                    if (jwtUtil.isValid(token)) {
                        Claims claims = jwtUtil.validate(token);
                        String rolesHeader = extractRoles(claims.get("roles"));
                        String nombreClaim = claims.get("nombre", String.class);
                        log.info("[GATEWAY] Ruta pública {} {}: token válido, subject={}, roles={}",
                                method, path, claims.getSubject(), rolesHeader);
                        ServerHttpRequest mutatedRequest = request.mutate()
                                .header("X-User-Id", String.valueOf(claims.getSubject()))
                                .header("X-User-Roles", rolesHeader)
                                .header("X-User-Name", nombreClaim != null ? nombreClaim : "")
                                .build();
                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    }
                    log.warn("[GATEWAY] Token inválido en ruta pública: {} {} — permitiendo acceso anónimo", method, path);
                    return chain.filter(exchange);
                }
                log.debug("[GATEWAY] Ruta pública {} {}: sin token, acceso anónimo", method, path);
                return chain.filter(exchange);
            }

            // Rutas protegidas: exigir token válido
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
            String rolesHeader = extractRoles(claims.get("roles"));
            String nombreClaim = claims.get("nombre", String.class);
            log.info("JWT válido — subject: {}, roles propagados: {}, path: {}", claims.getSubject(), rolesHeader, path);
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", String.valueOf(claims.getSubject()))
                    .header("X-User-Roles", rolesHeader)
                    .header("X-User-Name", nombreClaim != null ? nombreClaim : "")
                    .build();

            log.info("Headers enviados a downstream: X-User-Roles={}, X-User-Id={}",
                    mutatedRequest.getHeaders().getFirst("X-User-Roles"),
                    mutatedRequest.getHeaders().getFirst("X-User-Id"));

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        };
    }

    /**
     * Normaliza el claim "roles" del JWT a una cadena CSV en mayúsculas.
     * Maneja tanto String ("ADMIN") como List (["ADMIN","USER"]) que jsonwebtoken
     * puede retornar según cómo fue generado el token.
     * Resultado: "ADMIN" o "ADMIN,USER" — sin corchetes ni espacios.
     */
    private String extractRoles(Object rolesObj) {
        if (rolesObj == null) return "";
        if (rolesObj instanceof List<?> list) {
            return list.stream()
                    .map(r -> r.toString().toUpperCase())
                    .collect(Collectors.joining(","));
        }
        return rolesObj.toString().toUpperCase();
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
