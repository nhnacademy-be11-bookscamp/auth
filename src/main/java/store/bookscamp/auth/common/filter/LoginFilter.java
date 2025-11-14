package store.bookscamp.auth.common.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import store.bookscamp.auth.common.config.JWTUtil;
import store.bookscamp.auth.repository.RefreshTokenRepository;
import store.bookscamp.auth.controller.request.MemberLoginRequest;
import store.bookscamp.auth.service.CustomMemberDetails;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
        setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (request.getContentType() != null && request.getContentType().contains("application/json")) {
            try {
                MemberLoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), MemberLoginRequest.class);
                String username = loginRequest.username();
                String password = loginRequest.password();
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(username, password, null);
                return authenticationManager.authenticate(authToken);
            } catch (IOException e) {
                throw new RuntimeException("JSON body parsing failed for login request", e);
            }
        }
        return super.attemptAuthentication(request, response);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException {

        CustomMemberDetails customUserDetails = (CustomMemberDetails) authentication.getPrincipal();

        Long memberId = customUserDetails.getId();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        String name = customUserDetails.getName();

        String accessToken = jwtUtil.createAccessToken(memberId, role);
        String refreshToken = jwtUtil.createRefreshToken(memberId, role);

        String userKey = role + ":" + memberId;
        refreshTokenRepository.save(userKey, refreshToken, JWTUtil.REFRESH_TOKEN_EXPIRATION_MS);

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("accessToken", accessToken);
        responseBody.put("name", name);


        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.addHeader("Set-Cookie", createCookie(refreshToken,request));
        response.setStatus(HttpServletResponse.SC_OK);

        objectMapper.writeValue(response.getWriter(), responseBody);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("LoginFailed");
    }

    private String createCookie(String refreshToken, HttpServletRequest request) {

        boolean isSecure = request.isSecure();
        if (request.getHeader("x-forwarded-proto") != null) {
            isSecure = request.getHeader("x-forwarded-proto").equals("https");
        }

        long maxAge = JWTUtil.REFRESH_TOKEN_EXPIRATION_MS / 1000;

        String sameSitePolicy = isSecure ? "None" : "Lax";
        String secureFlag = isSecure ? " Secure;" : "";

        return String.format(
                "refresh_token=%s; Path=/; Max-Age=%d; HttpOnly;%s SameSite=%s",
                refreshToken, maxAge, secureFlag, sameSitePolicy
        );
    }
}