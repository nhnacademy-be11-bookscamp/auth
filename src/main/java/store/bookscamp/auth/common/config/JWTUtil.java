package store.bookscamp.auth.common.config;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Component
public class JWTUtil {

    public static final Long ACCESS_TOKEN_EXPIRATION_MS = 1000 * 60 * 30L;
    public static final Long REFRESH_TOKEN_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 7L;
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public Long getMemberId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("memberId", Long.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public Boolean isExpired(String token) {
        Instant expirationInstant = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().toInstant();
        return expirationInstant.isBefore(Instant.now());
    }

    public String createAccessToken(Long memberId, String role) {
        return createJwt("access", memberId, role, ACCESS_TOKEN_EXPIRATION_MS);
    }

    public String createRefreshToken(Long memberId, String role) {
        return createJwt("refresh", memberId, role, REFRESH_TOKEN_EXPIRATION_MS);
    }

    private String createJwt(String category, Long memberId, String role, Long expiredMs) {
        Instant issuedAt = Instant.now();
        Instant expiration = issuedAt.plusMillis(expiredMs);

        return Jwts.builder()
                .claim("category", category)
                .claim("id", memberId)
                .claim("role", role)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiration))
                .signWith(secretKey)
                .compact();
    }
}