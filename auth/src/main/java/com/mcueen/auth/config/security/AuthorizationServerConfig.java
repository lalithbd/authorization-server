package com.mcueen.auth.config.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.filter.AuthenticationFilterHelper;
import com.mcueen.auth.config.security.filter.ClientAuthenticator;
import com.mcueen.auth.config.security.filter.CustomTokenHandler;
import com.mcueen.auth.config.security.filter.OAuthCallbackHandler;
import com.mcueen.auth.config.security.filter.RefreshTokenHandler;
import com.mcueen.auth.config.security.filter.TokenIntrospectionHandler;
import com.mcueen.auth.config.security.filter.UsernamePasswordAuthHandler;
import com.mcueen.auth.config.security.handler.CustomAuthenticationEntryPoint;
import com.mcueen.auth.config.security.provider.FederatedAuthenticationProvider;
import com.mcueen.auth.config.security.provider.RefreshTokenAuthenticationProvider;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import com.mcueen.auth.util.auth.AuthEndpoints;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.cors.CorsConfigurationSource;
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

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Autowired
    private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private FederatedAuthenticationProvider federatedAuthenticationProvider;


    /**
     * The five handlers below are constructed here rather than being {@code @Component}s. Spring
     * Boot auto-registers every {@link Filter} bean against {@code /*}, which would run them a
     * second time outside this chain. Keeping them out of the context removes that possibility
     * instead of switching it off after the fact.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   OAuth2TokenGenerator<?> tokenGenerator,
                                                   AuthenticationManager authenticationManager,
                                                   AuthenticationFilterHelper authenticationFilterHelper,
                                                   ClientAuthenticator clientAuthenticator,
                                                   AuthProviderService authProviderService,
                                                   OAuth2AuthorizationServiceImpl oAuth2AuthorizationService,
                                                   ObjectMapper objectMapper,
                                                   CorsConfigurationSource corsConfigurationSource) throws Exception {

        UsernamePasswordAuthHandler usernamePasswordAuthHandler =
                new UsernamePasswordAuthHandler(authenticationFilterHelper, objectMapper, clientAuthenticator);
        OAuthCallbackHandler oAuthCallbackHandler =
                new OAuthCallbackHandler(authProviderService, objectMapper, clientAuthenticator);
        RefreshTokenHandler refreshTokenHandler =
                new RefreshTokenHandler(authenticationFilterHelper, objectMapper, clientAuthenticator);
        CustomTokenHandler customTokenHandler = new CustomTokenHandler(oAuth2AuthorizationService);
        TokenIntrospectionHandler tokenIntrospectionHandler =
                new TokenIntrospectionHandler(oAuth2AuthorizationService, objectMapper, clientAuthenticator);

        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(AuthEndpoints.TOKEN, AuthEndpoints.INTROSPECT, AuthEndpoints.PROVIDERS,
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
        // Introspection is intentionally left on the Spring Authorization Server default
        // (/oauth2/introspect). Remapping it to AuthEndpoints.INTROSPECT would hand that path to
        // the authorization server chain, which registers at HIGHEST_PRECEDENCE and would shadow
        // TokenIntrospectionHandler. Each path has exactly one owner.
        return AuthorizationServerSettings.builder()
                .tokenEndpoint(AuthEndpoints.TOKEN)
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(new OAuth2RefreshTokenGenerator(), new OAuth2AccessTokenGenerator());
    }
}
