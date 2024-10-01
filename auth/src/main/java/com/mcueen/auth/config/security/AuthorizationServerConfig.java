package com.mcueen.auth.config.security;

import com.mcueen.auth.config.security.converter.PasswordAuthenticationConverter;
import com.mcueen.auth.config.security.model.CustomUserDetailService;
import com.mcueen.auth.config.security.provider.CustomPasswordAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig extends OAuth2AuthorizationServerConfiguration {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CustomUserDetailService userDetailService;

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/abc").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable).build();
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.tokenGenerator(new OAuth2AccessTokenGenerator());
        authorizationServerConfigurer.tokenEndpoint(endPoint -> {
            endPoint.accessTokenRequestConverter(new PasswordAuthenticationConverter());
            endPoint.authenticationProvider(new CustomPasswordAuthenticationProvider(userDetailService, passwordEncoder));
        });
        return super.authorizationServerSecurityFilterChain(http);
    }

    @Bean
    public AuthenticationManager authServerAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
