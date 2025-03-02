package com.mcueen.auth.config.security;


import com.mcueen.auth.config.security.filter.UsernamePasswordAuthFilter;
import com.mcueen.auth.config.security.model.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2TokenGenerator<?> tokenGenerator, AuthenticationManager authenticationManager) throws Exception {

        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/token").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterAfter(new UsernamePasswordAuthFilter(authenticationManager, tokenGenerator), UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint("/token")
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(
                new OAuth2AccessTokenGenerator(),
                new OAuth2RefreshTokenGenerator()
        );
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getPrincipal() != null) {
                context.getClaims().claim("user_name", context.getPrincipal().getName());
            }
        };
    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new ClientRegistrationRepository();
//    }
//    @Bean
//    public OAuth2AccessTokenResponseAuthenticationSuccessHandler oAuth2AccessTokenResponseAuthenticationSuccessHandler() {
//        return new OAuth2AccessTokenResponseAuthenticationSuccessHandler();
//    }

}
