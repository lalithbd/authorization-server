package com.mcueen.auth.config.security;


import com.mcueen.auth.config.security.filter.CustomTokenFilter;
import com.mcueen.auth.config.security.filter.RefreshTokenFilter;
import com.mcueen.auth.config.security.filter.UsernamePasswordAuthFilter;
import com.mcueen.auth.config.security.handler.CustomAuthenticationEntryPoint;
import com.mcueen.auth.config.security.model.CustomOAuth2AuthorizationService;
import com.mcueen.auth.config.security.model.CustomUserDetailService;
import com.mcueen.auth.config.security.provider.CustomPasswordAuthenticationProvider;
import com.mcueen.auth.config.security.provider.RefreshTokenAuthenticationProvider;
import com.mcueen.auth.service.JpaTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Autowired
    @Lazy
    private JpaTokenService jpaTokenService;

    @Autowired
    private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;

    @Autowired
    private CustomPasswordAuthenticationProvider customPasswordAuthenticationProvider;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private UsernamePasswordAuthFilter usernamePasswordAuthFilter;

    @Autowired
    private RefreshTokenFilter refreshTokenFilter;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2TokenGenerator<?> tokenGenerator, AuthenticationManager authenticationManager) throws Exception {

        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/token").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterAfter(usernamePasswordAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new CustomTokenFilter(jpaTokenService), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandlingConfigurer -> exceptionHandlingConfigurer
                        .accessDeniedHandler(new AccessDeniedHandlerImpl())
                        .authenticationEntryPoint(customAuthenticationEntryPoint))
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(refreshTokenAuthenticationProvider, customPasswordAuthenticationProvider);
    }
}
