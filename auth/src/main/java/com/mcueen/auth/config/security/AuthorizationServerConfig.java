package com.mcueen.auth.config.security;


import com.mcueen.auth.config.security.converter.PasswordAuthenticationConverter;
import com.mcueen.auth.config.security.filter.CustomAuthenticationFilter;
import com.mcueen.auth.config.security.model.CustomClientDetailsService;
import com.mcueen.auth.config.security.model.CustomUserDetailService;
import com.mcueen.auth.config.security.provider.CustomPasswordAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig /*extends OAuth2AuthorizationServerConfiguration*/ {

    @Autowired
    private CustomUserDetailService userDetailService;

    @Autowired
    private CustomClientDetailsService customClientDetailsService;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/token", "/user/login").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(new CustomAuthenticationFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class)
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


//    @Bean
//    public AuthorizationServerTokenServices tokenServices(DataSource dataSource){
//        DefaultTokenServices tokenServices =  new DefaultTokenServices();
//        tokenServices.setTokenStore(new JdbcTokenStore(dataSource));
//        tokenServices.setReuseRefreshToken(false);
//        tokenServices.setSupportRefreshToken(true);
//        tokenServices.setClientDetailsService(customClientDetailsService);
//        return tokenServices;
//    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getPrincipal() != null) {
                context.getClaims().claim("user_name", context.getPrincipal().getName());
            }
        };
    }

}
