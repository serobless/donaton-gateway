package cl.duocuc.dsy1106.gateway.filter;

import cl.duocuc.dsy1106.gateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JwtAuthFilterTest {

    private static final String BASE64_SECRET = "ZG9uYXRvbi1tcy1hdXRoLXNlY3JldC1rZXktZHVvY3VjLWRzeTExMDY=";

    private GatewayFilter filter;
    private GatewayFilterChain chain;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        JwtUtil jwtUtil = new JwtUtil(BASE64_SECRET);
        JwtAuthFilter filterFactory = new JwtAuthFilter(
                jwtUtil,
                List.of("/auth/login", "/auth/register", "/bff/portada", "/api/testimonios")
        );
        filter = filterFactory.apply(new JwtAuthFilter.Config());
        chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        byte[] keyBytes = Base64.getDecoder().decode(BASE64_SECRET);
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String buildValidToken(String subject) {
        return Jwts.builder()
                .subject(subject)
                .claim("roles", "DONADOR")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(signingKey)
                .compact();
    }

    private String buildExpiredToken() {
        return Jwts.builder()
                .subject("1")
                .claim("roles", "DONADOR")
                .issuedAt(new Date(System.currentTimeMillis() - 120_000))
                .expiration(new Date(System.currentTimeMillis() - 60_000))
                .signWith(signingKey)
                .compact();
    }

    @Test
    void testPublicPath_noToken_chainIsCalled() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        verify(chain, times(1)).filter(any());
        assertNotEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void testProtectedPath_noToken_returns401() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/donaciones").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(chain, never()).filter(any());
    }

    @Test
    void testProtectedPath_validToken_propagatesXUserIdHeader() {
        String token = buildValidToken("42");
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/donaciones")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        verify(chain, times(1)).filter(argThat(ex -> {
            String userId = ex.getRequest().getHeaders().getFirst("X-User-Id");
            return "42".equals(userId);
        }));
    }

    @Test
    void testProtectedPath_expiredToken_returns401() {
        String expired = buildExpiredToken();
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/donaciones")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expired)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void testProtectedPath_malformedToken_returns401() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/causas/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token.malformado.xyz")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }
}
