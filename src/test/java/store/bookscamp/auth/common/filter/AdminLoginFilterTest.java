package store.bookscamp.auth.common.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.controller.request.AdminLoginRequest;
import store.bookscamp.auth.repository.RefreshTokenRepository;
import store.bookscamp.auth.service.CustomAdminDetails;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AdminLoginFilterTest {

    @Mock AuthenticationManager authenticationManager;
    @Mock JWTUtil jwtUtil;
    @Mock RefreshTokenRepository refreshTokenRepository;
    @Mock FilterChain filterChain;
    @Mock Authentication authentication;
    @Mock CustomAdminDetails customAdminDetails;

    private AdminLoginFilter adminLoginFilter;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        adminLoginFilter = new AdminLoginFilter(authenticationManager, jwtUtil, refreshTokenRepository);
    }

    @Test
    @DisplayName("인증 시도: JSON 요청 파싱 확인")
    void attemptAuthentication() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        AdminLoginRequest loginRequest = new AdminLoginRequest("admin", "1234");
        request.setContent(objectMapper.writeValueAsBytes(loginRequest));
        MockHttpServletResponse response = new MockHttpServletResponse();

        adminLoginFilter.attemptAuthentication(request, response);

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("인증 성공: 토큰 발급 및 저장")
    void successfulAuthentication() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        given(customAdminDetails.getId()).willReturn(100L);
        given(customAdminDetails.getName()).willReturn("SuperAdmin");

        given(authentication.getPrincipal()).willReturn(customAdminDetails);
        doReturn(List.of(new SimpleGrantedAuthority("ADMIN"))).when(authentication).getAuthorities();

        given(jwtUtil.createAccessToken(anyLong(), anyString())).willReturn("access_token");
        given(jwtUtil.createRefreshToken(anyLong(), anyString())).willReturn("refresh_token");

        adminLoginFilter.successfulAuthentication(request, response, filterChain, authentication);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

        assertThat(response.getHeader("Set-Cookie")).isNotNull();
        assertThat(response.getHeader("Set-Cookie")).contains("refresh_token=refresh_token");

        verify(refreshTokenRepository).save(contains(":100"), eq("refresh_token"), anyLong());
    }

    @Test
    @DisplayName("인증 실패: 401 반환")
    void unsuccessfulAuthentication() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        adminLoginFilter.unsuccessfulAuthentication(request, response, new AuthenticationException("Fail") {});

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentAsString()).isEqualTo("LoginFailed");
    }
}