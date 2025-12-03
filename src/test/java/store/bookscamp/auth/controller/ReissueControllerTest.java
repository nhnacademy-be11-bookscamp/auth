package store.bookscamp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.controller.request.OauthLoginRequest;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.repository.MemberCredentialRepository;
import store.bookscamp.auth.repository.RefreshTokenRepository;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = ReissueController.class)
@AutoConfigureMockMvc(addFilters = false)
class ReissueControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockitoBean JWTUtil jwtUtil;
    @MockitoBean RefreshTokenRepository refreshTokenRepository;
    @MockitoBean MemberCredentialRepository memberCredentialRepository;

    @Test
    @DisplayName("소셜 로그인 성공: 액세스 토큰과 쿠키 발급")
    @WithMockUser
    void oauthLogin_Success() throws Exception {
        String username = "google_12345";
        OauthLoginRequest request = new OauthLoginRequest(username);

        Member member = new Member(username, "N/A");
        org.springframework.test.util.ReflectionTestUtils.setField(member, "id", 1L);
        org.springframework.test.util.ReflectionTestUtils.setField(member, "name", "Tester");

        given(memberCredentialRepository.getByUsername(username)).willReturn(Optional.of(member));
        given(jwtUtil.createAccessToken(anyLong(), anyString())).willReturn("new_access_token");
        given(jwtUtil.createRefreshToken(anyLong(), anyString())).willReturn("new_refresh_token");

        mockMvc.perform(post("/oauth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new_access_token"))
                .andExpect(jsonPath("$.name").value("Tester"))
                .andExpect(header().exists("Set-Cookie")); // 쿠키 생성 확인

        verify(refreshTokenRepository).save(eq("USER:1"), eq("new_refresh_token"), anyLong());
    }

    @Test
    @DisplayName("재발급 성공")
    @WithMockUser
    void reissue_Success() throws Exception {
        String refreshToken = "valid_refresh_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willReturn(false);
        given(jwtUtil.getCategory(refreshToken)).willReturn("refresh");
        given(jwtUtil.getMemberId(refreshToken)).willReturn(1L);
        given(jwtUtil.getRole(refreshToken)).willReturn("ROLE_USER");
        given(refreshTokenRepository.findByMemberId("ROLE_USER:1")).willReturn(refreshToken);

        given(jwtUtil.createAccessToken(anyLong(), any())).willReturn("new_access");
        given(jwtUtil.createRefreshToken(anyLong(), any())).willReturn("new_refresh");

        mockMvc.perform(post("/reissue")
                        .with(csrf())
                        .cookie(cookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new_access"))
                .andExpect(cookie().exists("refresh_token"));
    }

    @Test
    @DisplayName("재발급 실패: 쿠키가 없는 경우")
    void reissue_Fail_NoCookie() throws Exception {
        mockMvc.perform(post("/reissue")
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token is missing"));
    }

    @Test
    @DisplayName("재발급 실패: 토큰 만료 (Boolean check)")
    void reissue_Fail_Expired_Logic() throws Exception {
        String refreshToken = "expired_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willReturn(true);

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token is expired"));
    }

    @Test
    @DisplayName("재발급 실패: 토큰 만료 (ExpiredJwtException 발생)")
    void reissue_Fail_Expired_Exception() throws Exception {
        String refreshToken = "expired_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willThrow(new ExpiredJwtException(null, null, "Expired"));

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token is expired"));
    }

    @Test
    @DisplayName("재발급 실패: 카테고리가 refresh가 아님")
    void reissue_Fail_InvalidCategory() throws Exception {
        String refreshToken = "access_token_in_cookie";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willReturn(false);
        given(jwtUtil.getCategory(refreshToken)).willReturn("access"); // Not 'refresh'

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid token type"));
    }

    @Test
    @DisplayName("재발급 실패: Redis에 토큰 없음 (로그아웃됨)")
    void reissue_Fail_NotInRedis() throws Exception {
        String refreshToken = "valid_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willReturn(false);
        given(jwtUtil.getCategory(refreshToken)).willReturn("refresh");
        given(jwtUtil.getMemberId(refreshToken)).willReturn(1L);
        given(jwtUtil.getRole(refreshToken)).willReturn("USER");

        given(refreshTokenRepository.findByMemberId("USER:1")).willReturn(null); // Redis 없음

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token not found"));
    }

    @Test
    @DisplayName("재발급 실패: Redis 토큰과 불일치 (토큰 탈취 의심)")
    void reissue_Fail_TokenMismatch() throws Exception {
        String refreshToken = "client_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willReturn(false);
        given(jwtUtil.getCategory(refreshToken)).willReturn("refresh");
        given(jwtUtil.getMemberId(refreshToken)).willReturn(1L);
        given(jwtUtil.getRole(refreshToken)).willReturn("USER");

        given(refreshTokenRepository.findByMemberId("USER:1")).willReturn("different_redis_token");

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token mismatch"));

        verify(refreshTokenRepository).deleteByMemberId("USER:1");
    }

    @Test
    @DisplayName("재발급 실패: 유효하지 않은 토큰 포맷 (JwtException)")
    void reissue_Fail_JwtException() throws Exception {
        String refreshToken = "malformed_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.isExpired(refreshToken)).willThrow(new JwtException("Malformed"));

        mockMvc.perform(post("/reissue").cookie(cookie).with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid refresh token"));
    }

    @Test
    @DisplayName("로그아웃 성공")
    void logout_Success() throws Exception {
        String refreshToken = "token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.getMemberIdFromExpiredToken(refreshToken)).willReturn(1L);
        given(jwtUtil.getRoleFromExpiredToken(refreshToken)).willReturn("ROLE_USER");

        mockMvc.perform(post("/logout").with(csrf()).cookie(cookie))
                .andExpect(status().isOk());

        verify(refreshTokenRepository).deleteByMemberId("ROLE_USER:1");
    }

    @Test
    @DisplayName("로그아웃: 쿠키가 없어도 성공(OK) 반환")
    void logout_NoCookie_Success() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그아웃 실패: 토큰 정보 파싱 실패 (null 반환)")
    void logout_Fail_InvalidTokenData() throws Exception {
        String refreshToken = "invalid_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.getMemberIdFromExpiredToken(refreshToken)).willReturn(null);

        mockMvc.perform(post("/logout").with(csrf()).cookie(cookie))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("로그아웃 실패: 처리 중 예외 발생")
    void logout_Fail_Exception() throws Exception {
        String refreshToken = "token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.getMemberIdFromExpiredToken(refreshToken)).willThrow(new RuntimeException("Redis Error"));

        mockMvc.perform(post("/logout").with(csrf()).cookie(cookie))
                .andExpect(status().isInternalServerError());
    }
}