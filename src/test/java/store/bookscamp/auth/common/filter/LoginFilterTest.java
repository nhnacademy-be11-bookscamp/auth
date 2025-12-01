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
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.controller.request.MemberLoginRequest;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.repository.MemberCredentialRepository;
import store.bookscamp.auth.repository.RefreshTokenRepository;
import store.bookscamp.auth.service.CustomMemberDetails;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginFilterTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private JWTUtil jwtUtil;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private MemberCredentialRepository memberCredentialRepository;
    @Mock private FilterChain filterChain;
    @Mock private Authentication authentication;
    @Mock private CustomMemberDetails customMemberDetails;

    private LoginFilter loginFilter;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        loginFilter = new LoginFilter(authenticationManager, jwtUtil, refreshTokenRepository, memberCredentialRepository);
    }

    @Test
    @DisplayName("인증 시도: JSON 요청을 파싱하여 AuthenticationManager에게 위임한다")
    void attemptAuthentication_Success() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        MemberLoginRequest loginRequest = new MemberLoginRequest("user1", "1234");
        request.setContent(objectMapper.writeValueAsBytes(loginRequest));

        MockHttpServletResponse response = new MockHttpServletResponse();

        loginFilter.attemptAuthentication(request, response);

        verify(authenticationManager).authenticate(argThat(auth ->
                auth.getPrincipal().equals("user1") && auth.getCredentials().equals("1234")
        ));
    }

    @Test
    @DisplayName("인증 성공: 중복 로그인이면 409 Conflict를 반환한다")
    void successfulAuthentication_ConcurrentLoginBlocked() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        Member member = new Member("user1", "pw");
        ReflectionTestUtils.setField(member, "id", 1L);
        ReflectionTestUtils.setField(member, "name", "User");

        given(customMemberDetails.getMember()).willReturn(member);
        given(authentication.getPrincipal()).willReturn(customMemberDetails);

        doReturn(List.of(new SimpleGrantedAuthority("ROLE_USER"))).when(authentication).getAuthorities();

        given(refreshTokenRepository.findByMemberId("ROLE_USER:1")).willReturn("existing_refresh_token");

        loginFilter.successfulAuthentication(request, response, filterChain, authentication);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_CONFLICT);
        Map<String, String> responseBody = objectMapper.readValue(response.getContentAsString(), Map.class);
        assertThat(responseBody.get("error")).isEqualTo("ALREADY_LOGGED_IN");

        verify(refreshTokenRepository, never()).save(any(), any(), anyLong());    }

    @Test
    @DisplayName("인증 성공: 정상 로그인이면 토큰을 발급하고 쿠키와 바디에 담는다")
    void successfulAuthentication_Success() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        Member member = new Member("user1", "pw");
        ReflectionTestUtils.setField(member, "id", 1L);
        ReflectionTestUtils.setField(member, "name", "User");

        given(customMemberDetails.getMember()).willReturn(member);
        given(authentication.getPrincipal()).willReturn(customMemberDetails);

        doReturn(List.of(new SimpleGrantedAuthority("ROLE_USER"))).when(authentication).getAuthorities();

        given(refreshTokenRepository.findByMemberId("ROLE_USER:1")).willReturn(null);

        given(jwtUtil.createAccessToken(1L, "ROLE_USER")).willReturn("access_token");
        given(jwtUtil.createRefreshToken(1L, "ROLE_USER")).willReturn("refresh_token");

        loginFilter.successfulAuthentication(request, response, filterChain, authentication);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

        Map<String, String> responseBody = objectMapper.readValue(response.getContentAsString(), Map.class);
        assertThat(responseBody.get("accessToken")).isEqualTo("access_token");

        assertThat(response.getHeader("Set-Cookie")).contains("refresh_token=refresh_token");

        verify(refreshTokenRepository).save(eq("ROLE_USER:1"), eq("refresh_token"), anyLong());
        verify(memberCredentialRepository).save(member);
    }

    @Test
    @DisplayName("인증 실패: 휴면 계정(DisabledException)이면 401과 전용 헤더를 반환한다")
    void unsuccessfulAuthentication_Dormant() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = new DisabledException("Account is disabled");

        loginFilter.unsuccessfulAuthentication(request, response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getHeader("X-AUTH-ERROR-CODE")).isEqualTo("DORMANT_MEMBER");
        assertThat(response.getContentAsString()).contains("DORMANT_MEMBER");
    }

    @Test
    @DisplayName("인증 실패: 일반 실패는 401과 JSON 에러 바디를 반환한다")
    void unsuccessfulAuthentication_General() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = new AuthenticationException("Bad credentials") {};

        loginFilter.unsuccessfulAuthentication(request, response, exception);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        Map<String, String> responseBody = objectMapper.readValue(response.getContentAsString(), Map.class);
        assertThat(responseBody.get("code")).isEqualTo("LOGIN_FAILED");
    }
}