package com.mcueen.auth.config.security;


import com.mcueen.auth.config.security.filter.CustomTokenHandler;
import com.mcueen.auth.config.security.filter.RefreshTokenHandler;
import com.mcueen.auth.config.security.filter.TokenIntrospectionFilter;
import com.mcueen.auth.config.security.filter.UsernamePasswordAuthHandler;
import com.mcueen.auth.config.security.model.CustomUserDetailService;
import com.mcueen.auth.config.security.provider.CustomPasswordAuthenticationProvider;
import com.mcueen.auth.config.security.provider.RefreshTokenAuthenticationProvider;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Autowired
    private CustomUserDetailService userDetailService;

    @Autowired
    private OAuth2AuthorizationServiceImpl jpaTokenService;

    @Autowired
    private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;

    @Autowired
    private CustomPasswordAuthenticationProvider customPasswordAuthenticationProvider;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2TokenGenerator<?> tokenGenerator, AuthenticationManager authenticationManager) throws Exception {

        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/auth/token", "/auth/introspect").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterAfter(new UsernamePasswordAuthHandler(authenticationManager, jpaTokenService, tokenGenerator), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new RefreshTokenHandler(authenticationManager, jpaTokenService, tokenGenerator), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new CustomTokenHandler(jpaTokenService), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new TokenIntrospectionFilter(jpaTokenService), UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return new ProviderManager(customPasswordAuthenticationProvider, refreshTokenAuthenticationProvider);
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint("/token")
                .tokenIntrospectionEndpoint("/auth/introspect")
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(new OAuth2RefreshTokenGenerator(), new OAuth2AccessTokenGenerator());
    }
}
