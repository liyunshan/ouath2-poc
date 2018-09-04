package com.aaxis.oauth2.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import com.aaxis.oauth2.token.TokenManager;

@Configuration
public class OAuth2TokenStoreConfig {
    
    @Autowired
    private TokenManager tokenManager;
    
    @Autowired
    @Qualifier("oauth2Datasource")
    private DataSource dataSource; 

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("123");
        return converter;
    }
    
    
    @Bean
    public TokenStore tokenStore() {
       return this.tokenManager.getTokenStore(dataSource, jwtAccessTokenConverter());
    }
    
}
