package store.bookscamp.auth.common.config;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JWTUtilTest {

    private JWTUtil jwtUtil;

    private static final String TEST_SECRET = "testSecretKeyTestSecretKeyTestSecretKeyTestSecretKey";

    @BeforeEach
    void setUp() {
        jwtUtil = new JWTUtil(TEST_SECRET);
    }

    @Test
    @DisplayName("Access Token 생성 및 파싱 테스트")
    void createAndParseAccessToken() {
        Long memberId = 123L;
        String role = "ROLE_USER";

        String token = jwtUtil.createAccessToken(memberId, role);

        assertThat(token).isNotNull();
        assertThat(jwtUtil.getMemberId(token)).isEqualTo(memberId);
        assertThat(jwtUtil.getRole(token)).isEqualTo(role);
        assertThat(jwtUtil.getCategory(token)).isEqualTo("access");
        assertThat(jwtUtil.isExpired(token)).isFalse();
    }

    @Test
    @DisplayName("Refresh Token 생성 및 파싱 테스트")
    void createAndParseRefreshToken() {
        Long memberId = 456L;
        String role = "ROLE_ADMIN";

        String token = jwtUtil.createRefreshToken(memberId, role);

        assertThat(token).isNotNull();
        assertThat(jwtUtil.getMemberId(token)).isEqualTo(memberId);
        assertThat(jwtUtil.getRole(token)).isEqualTo(role);
        assertThat(jwtUtil.getCategory(token)).isEqualTo("refresh");
        assertThat(jwtUtil.isExpired(token)).isFalse();
    }

    @Test
    @DisplayName("만료된 토큰에서 정보 추출 테스트")
    void getInfoFromExpiredToken() {
        Long memberId = 789L;
        String role = "ROLE_USER";

        SecretKey secretKey = new SecretKeySpec(TEST_SECRET.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        String expiredToken = Jwts.builder()
                .claim("id", memberId)
                .claim("role", role)
                .claim("category", "access")
                .issuedAt(new Date(System.currentTimeMillis() - 100000))
                .expiration(new Date(System.currentTimeMillis() - 10000))
                .signWith(secretKey)
                .compact();

        assertThat(jwtUtil.getMemberIdFromExpiredToken(expiredToken)).isEqualTo(memberId);
        assertThat(jwtUtil.getRoleFromExpiredToken(expiredToken)).isEqualTo(role);
    }
}