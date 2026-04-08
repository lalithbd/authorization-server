package com.mcueen.auth.config.security;


import com.mcueen.auth.config.security.filter.CustomTokenHandler;
import com.mcueen.auth.config.security.filter.OAuthCallbackHandler;
import com.mcueen.auth.config.security.filter.RefreshTokenHandler;
import com.mcueen.auth.config.security.filter.TokenIntrospectionHandler;
import com.mcueen.auth.config.security.filter.UsernamePasswordAuthHandler;
import com.mcueen.auth.config.security.handler.CustomAuthenticationEntryPoint;
import com.mcueen.auth.config.security.provider.FederatedAuthenticationProvider;
import com.mcueen.auth.config.security.provider.RefreshTokenAuthenticationProvider;
import com.mcueen.auth.util.auth.AuthEndpoints;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Autowired
    private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;

    @Autowired
    private RefreshTokenHandler refreshTokenHandler;

    @Autowired
    private UsernamePasswordAuthHandler usernamePasswordAuthHandler;

    @Autowired
    private CustomTokenHandler customTokenHandler;

    @Autowired
    private OAuthCallbackHandler oAuthCallbackHandler;

    @Autowired
    private TokenIntrospectionHandler tokenIntrospectionHandler;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private FederatedAuthenticationProvider federatedAuthenticationProvider;

    @Value("${cors.allowed-origins:http://localhost:3000}")
    private List<String> allowedOrigins;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2TokenGenerator<?> tokenGenerator, AuthenticationManager authenticationManager) throws Exception {

        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(AuthEndpoints.TOKEN, AuthEndpoints.INTROSPECT, AuthEndpoints.PROVIDERS, AuthEndpoints.OAUTH_CALLBACK,
                                AuthEndpoints.SWAGGER_UI, AuthEndpoints.API_DOCS, AuthEndpoints.SWAGGER_HTML).permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterAfter(usernamePasswordAuthHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(oAuthCallbackHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(customTokenHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(tokenIntrospectionHandler, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandlingConfigurer -> exceptionHandlingConfigurer
                        .accessDeniedHandler(new AccessDeniedHandlerImpl())
                        .authenticationEntryPoint(customAuthenticationEntryPoint))
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return new ProviderManager(federatedAuthenticationProvider, refreshTokenAuthenticationProvider);
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint(AuthEndpoints.TOKEN)
                .tokenIntrospectionEndpoint(AuthEndpoints.INTROSPECT)
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(new OAuth2RefreshTokenGenerator(), new OAuth2AccessTokenGenerator());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
