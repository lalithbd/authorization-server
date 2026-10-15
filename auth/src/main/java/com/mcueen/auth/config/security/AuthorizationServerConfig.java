package com.mcueen.auth.config.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.filter.*;
import com.mcueen.auth.config.security.handler.CustomAuthenticationEntryPoint;
import com.mcueen.auth.config.security.provider.FederatedAuthenticationProvider;
import com.mcueen.auth.config.security.provider.RefreshTokenAuthenticationProvider;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import com.mcueen.auth.util.auth.AuthEndpoints;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    private final RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;
    private final UsernamePasswordAuthHandler usernamePasswordAuthHandler;
    private final OAuthCallbackHandler oAuthCallbackHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final FederatedAuthenticationProvider federatedAuthenticationProvider;
    private final RefreshTokenHandler refreshTokenHandler;
    private final TokenIntrospectionHandler tokenIntrospectionHandler;
    private final CustomTokenHandler customTokenHandler;

    public AuthorizationServerConfig(RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider,
                                     CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                                     FederatedAuthenticationProvider federatedAuthenticationProvider,
                                     AuthenticationFilterHelper authenticationFilterHelper,
                                     AuthProviderService authProviderService,
                                     ObjectMapper objectMapper,
                                     OAuth2AuthorizationServiceImpl oAuth2AuthorizationService,
                                     RegisteredClientRepository registeredClientRepository) {
        this.refreshTokenAuthenticationProvider = refreshTokenAuthenticationProvider;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.federatedAuthenticationProvider = federatedAuthenticationProvider;
        this.usernamePasswordAuthHandler = new UsernamePasswordAuthHandler(authenticationFilterHelper, objectMapper);
        this.oAuthCallbackHandler = new OAuthCallbackHandler(authProviderService, objectMapper);
        this.refreshTokenHandler = new RefreshTokenHandler(authenticationFilterHelper, objectMapper);
        this.tokenIntrospectionHandler = new TokenIntrospectionHandler(oAuth2AuthorizationService, objectMapper, registeredClientRepository);
        this.customTokenHandler = new CustomTokenHandler(oAuth2AuthorizationService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   OAuth2TokenGenerator<?> tokenGenerator,
                                                   AuthenticationManager authenticationManager,
                                                   CorsConfigurationSource corsConfigurationSource) throws Exception {

        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(AuthEndpoints.TOKEN, AuthEndpoints.OAUTH2_INTROSPECT, AuthEndpoints.PROVIDERS,
                                AuthEndpoints.OAUTH_CALLBACK, AuthEndpoints.SIGNUP, AuthEndpoints.LOGIN,
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
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(new OAuth2RefreshTokenGenerator(), new OAuth2AccessTokenGenerator());
    }
}
