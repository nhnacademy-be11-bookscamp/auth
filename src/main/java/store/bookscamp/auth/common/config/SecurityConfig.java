package store.bookscamp.auth.common.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import store.bookscamp.auth.common.filter.AdminLoginFilter;
import store.bookscamp.auth.common.filter.LoginFilter;
import store.bookscamp.auth.service.AdminLoginService;
import store.bookscamp.auth.service.MemberLoginService;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final MemberLoginService memberLoginService;
    private final AdminLoginService adminLoginService;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtil jwtUtil;


    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(memberLoginService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public DaoAuthenticationProvider adminAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(adminLoginService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }


    @Bean
    @Order(1)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {

        http.securityMatcher("/admin/**");

        AuthenticationManager adminAuthManager = new ProviderManager(adminAuthenticationProvider());

        http.authenticationManager(adminAuthManager);

        http.csrf(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        .requestMatchers(HttpMethod.POST, "/**").permitAll()
                        .anyRequest().authenticated()
        );


        http.addFilterAt(new AdminLoginFilter(adminAuthManager,jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(adminAuthenticationProvider());

        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        AuthenticationManager memberAuthManager = new ProviderManager(authenticationProvider());

        http.authenticationManager(memberAuthManager);

        http.csrf(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        .requestMatchers(HttpMethod.POST, "/**").permitAll()
                        .anyRequest().authenticated()
        );

        http.addFilterAt(new LoginFilter(memberAuthManager,jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(authenticationProvider());

        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}