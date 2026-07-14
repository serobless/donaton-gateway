package cl.duocuc.dsy1106.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private static final String BASE64_SECRET = "ZG9uYXRvbi1tcy1hdXRoLXNlY3JldC1rZXktZHVvY3VjLWRzeTExMDY=";
    private static final String DIFFERENT_SECRET = Base64.getEncoder().encodeToString("otra-clave-completamente-diferente-larga".getBytes());

    private JwtUtil jwtUtil;
    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil(BASE64_SECRET);
        byte[] keyBytes = Base64.getDecoder().decode(BASE64_SECRET);
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String buildToken(String subject, long expiresInMs) {
        return Jwts.builder()
                .subject(subject)
                .claim("roles", "DONADOR")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiresInMs))
                .signWith(signingKey)
                .compact();
    }

    @Test
    void testValidToken_returnsClaimsWithSubject() {
        String token = buildToken("42", 60_000);
        Claims claims = jwtUtil.validate(token);
        assertEquals("42", claims.getSubject());
    }

    @Test
    void testValidToken_returnsRolesClaim() {
        String token = buildToken("7", 60_000);
        Claims claims = jwtUtil.validate(token);
        assertEquals("DONADOR", claims.get("roles"));
    }

    @Test
    void testExpiredToken_throwsJwtException() {
        String expired = buildToken("1", -1_000);
        assertThrows(JwtException.class, () -> jwtUtil.validate(expired));
    }

    @Test
    void testInvalidSignature_throwsJwtException() {
        byte[] otherBytes = Base64.getDecoder().decode(DIFFERENT_SECRET);
        SecretKey otherKey = Keys.hmacShaKeyFor(otherBytes);
        String wrongToken = Jwts.builder()
                .subject("99")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(otherKey)
                .compact();
        assertThrows(JwtException.class, () -> jwtUtil.validate(wrongToken));
    }

    @Test
    void testIsValid_withValidToken_returnsTrue() {
        String token = buildToken("5", 60_000);
        assertTrue(jwtUtil.isValid(token));
    }

    @Test
    void testIsValid_withExpiredToken_returnsFalse() {
        String expired = buildToken("5", -1_000);
        assertFalse(jwtUtil.isValid(expired));
    }

    @Test
    void testIsValid_withMalformedToken_returnsFalse() {
        assertFalse(jwtUtil.isValid("esto.no.es.un.jwt.valido"));
    }
}
