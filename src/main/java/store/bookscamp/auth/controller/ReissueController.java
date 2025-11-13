package store.bookscamp.auth.controller;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.repository.RefreshTokenRepository;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response) {

        if (refreshToken == null) {
            log.warn("Refresh token cookie is missing.");
            return new ResponseEntity<>("Refresh token is missing", HttpStatus.UNAUTHORIZED);
        }

        try {
            if (jwtUtil.isExpired(refreshToken)) {
                log.warn("Refresh token is expired.");
                return new ResponseEntity<>("Refresh token is expired", HttpStatus.UNAUTHORIZED);
            }
            String category = jwtUtil.getCategory(refreshToken);
            if (!"refresh".equals(category)) {
                log.warn("Invalid token category.");
                return new ResponseEntity<>("Invalid token type", HttpStatus.UNAUTHORIZED);
            }

            Long memberId = jwtUtil.getMemberId(refreshToken);
            String tokenInRedis = refreshTokenRepository.findByMemberId(memberId.toString());

            if (tokenInRedis == null) {
                log.warn("Refresh token not found in Redis (user logged out).");
                return new ResponseEntity<>("Refresh token not found", HttpStatus.UNAUTHORIZED);
            }
            if (!tokenInRedis.equals(refreshToken)) {
                log.warn("Refresh token mismatch (possible token theft).");

                refreshTokenRepository.deleteByMemberId(memberId.toString());
                return new ResponseEntity<>("Refresh token mismatch", HttpStatus.UNAUTHORIZED);
            }

            String role = jwtUtil.getRole(refreshToken);
            String newAccessToken = jwtUtil.createAccessToken(memberId, role);
            String newRefreshToken = jwtUtil.createRefreshToken(memberId, role);

            refreshTokenRepository.save(memberId.toString(), newRefreshToken, JWTUtil.REFRESH_TOKEN_EXPIRATION_MS);

            response.addHeader("Set-Cookie", createCookie(newRefreshToken));
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            String jsonResponse = "{\"accessToken\": \"" + newAccessToken + "\"}";

            return ResponseEntity.ok(jsonResponse);

        } catch (ExpiredJwtException e) {
            log.warn("Refresh token expired (JWT exception).");
            return new ResponseEntity<>("Refresh token is expired", HttpStatus.UNAUTHORIZED);
        } catch (JwtException e) {
            log.warn("Invalid refresh token: {}", e.getMessage());
            return new ResponseEntity<>("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }
    }


    private String createCookie(String refreshToken) {
        long maxAge = JWTUtil.REFRESH_TOKEN_EXPIRATION_MS / 1000;
        return String.format("refresh_token=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict",
                refreshToken, maxAge);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken != null) {
            try {
                Long memberId = jwtUtil.getMemberId(refreshToken);
                refreshTokenRepository.deleteByMemberId(memberId.toString());
            } catch (Exception e) {
            }
        }
        return ResponseEntity.ok().build();
    }
}