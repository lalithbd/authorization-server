package com.mcueen.auth.config.security;

//import com.mcueen.auth.config.security.model.CustomClientDetailsService;
import com.mcueen.auth.config.security.model.CustomClientDetailsService;
import com.mcueen.auth.config.security.model.CustomUserDetailService;

import com.mcueen.auth.config.security.provider.CustomPasswordAuthenticationProvider;
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
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
//@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig extends OAuth2AuthorizationServerConfiguration {

    @Autowired
    private CustomUserDetailService userDetailService;

    @Autowired
    private CustomClientDetailsService customClientDetailsService;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/token").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authenticationProvider(new CustomPasswordAuthenticationProvider(userDetailService, passwordEncoder()))
                .build();
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
//        authorizationServerConfigurer.tokenGenerator(new OAuth2AccessTokenGenerator());
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration, DataSource dataSource) throws Exception {
        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
//        authenticationManager.setClientDetailsService(customClientDetailsService);
//        authenticationManager.setTokenServices((ResourceServerTokenServices) tokenServices(dataSource));
//        return authenticationManager;
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


//    @Bean
//    public AuthorizationServerTokenServices tokenServices(DataSource dataSource){
//        DefaultTokenServices tokenServices =  new DefaultTokenServices();
//        tokenServices.setTokenStore(new JdbcTokenStore(dataSource));
//        tokenServices.setReuseRefreshToken(false);
//        tokenServices.setSupportRefreshToken(true);
//        tokenServices.setClientDetailsService(customClientDetailsService);
//        return tokenServices;
//    }

}
