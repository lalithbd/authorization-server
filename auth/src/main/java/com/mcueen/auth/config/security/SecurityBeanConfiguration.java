package com.mcueen.auth.config.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import javax.sql.DataSource;

@Configuration
public class SecurityBeanConfiguration {

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint("/token")
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(new OAuth2RefreshTokenGenerator(), new OAuth2AccessTokenGenerator());
    }

    @Bean
    public JdbcOAuth2AuthorizationService OAuth2AuthorizationService(DataSource dataSource, RegisteredClientRepository registeredClientRepository){
        return new JdbcOAuth2AuthorizationService(new JdbcTemplate(dataSource), registeredClientRepository);
    }

    @Bean
    @ConfigurationProperties("spring.datasource")
    public DataSource dataSource() {
        return DataSourceBuilder.create().build();
    }
}
