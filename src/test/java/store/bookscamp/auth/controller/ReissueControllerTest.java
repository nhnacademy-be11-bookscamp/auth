package store.bookscamp.auth.controller;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.repository.MemberCredentialRepository;
import store.bookscamp.auth.repository.RefreshTokenRepository;
import static org.mockito.Mockito.verify;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = ReissueController.class)
@AutoConfigureMockMvc(addFilters = false)
class ReissueControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean JWTUtil jwtUtil;
    @MockitoBean RefreshTokenRepository refreshTokenRepository;
    @MockitoBean MemberCredentialRepository memberCredentialRepository;

    @Test
    @DisplayName("토큰 재발급 성공")
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
    @DisplayName("로그아웃 성공")
    void logout_Success() throws Exception {
        String refreshToken = "expired_refresh_token";
        Cookie cookie = new Cookie("refresh_token", refreshToken);

        given(jwtUtil.getMemberIdFromExpiredToken(refreshToken)).willReturn(1L);
        given(jwtUtil.getRoleFromExpiredToken(refreshToken)).willReturn("ROLE_USER");

        mockMvc.perform(post("/logout")
                        .cookie(cookie))
                .andExpect(status().isOk());

        verify(refreshTokenRepository).deleteByMemberId("ROLE_USER:1");
    }
}