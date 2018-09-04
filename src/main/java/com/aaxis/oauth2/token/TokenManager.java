package com.aaxis.oauth2.token;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JWTTokenStoreDecorator;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.aaxis.oauth2.token.store.TokenStorePolicy;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TokenManager implements InitializingBean {

    @Value("${spring.oauth2.token-store-policy}")
    private String tokenStorePolicy;
    
    
    @Autowired
    @Qualifier("oauth2Datasource")
    private DataSource dataSource; 
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    private JdbcTemplate jdbcTemplate;
    
    public boolean removeToken(Principal principal, String username, String password) {
        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException(
                    "There is no client authentication. Try adding an appropriate authentication filter.");
        }
        String clientId = getClientId(principal);
        Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
        try {
            userAuth = authenticationManager.authenticate(userAuth);
        }
        catch (AccountStatusException ase) {
            //covers expired, locked, disabled cases (mentioned in section 5.2, draft 31)
            throw new InvalidGrantException(ase.getMessage());
        }
        catch (BadCredentialsException e) {
            // If the username/password are wrong the spec says we should send 400/invalid grant
            throw new InvalidGrantException(e.getMessage());
        }
        if (userAuth == null || !userAuth.isAuthenticated()) {
            throw new InvalidGrantException("Could not authenticate user: " + username);
        }
        
        return removeToken(clientId, username);
    }
    
    
    public boolean removeToken(String clientId, String username) {
        
        NoScopeAuthenticationKeyGenerator generator = new NoScopeAuthenticationKeyGenerator();
        Map<String, String> values = new LinkedHashMap<>();
        if (!StringUtils.isEmpty(username)) {
            values.put(NoScopeAuthenticationKeyGenerator.USERNAME, username);
        }
        if (!StringUtils.isEmpty(clientId)) {
            values.put(NoScopeAuthenticationKeyGenerator.CLIENT_ID, clientId);
        }
        String key = generator.getKey(values);
        List<Map<String, Object>> results = this.jdbcTemplate.queryForList("select refresh_token from oauth_access_token where authentication_id = ?", key);
        if (!CollectionUtils.isEmpty(results)) {
            
            String refreshToken = null;
            if (null != results.get(0)) {
                refreshToken = (String)results.get(0).get("REFRESH_TOKEN");
            }
            this.jdbcTemplate.update("delete from oauth_access_token where authentication_id = ?", key);
            this.jdbcTemplate.update("delete from oauth_refresh_token where token_id = ?", refreshToken);
        
        }
        return false;
    }
    
    public TokenStore getTokenStore(DataSource dataSource, JwtAccessTokenConverter jwtAccessTokenConverter) {
        TokenStore tokenStore = null;
        TokenStorePolicy policy = TokenStorePolicy.valueOf(tokenStorePolicy);
        switch (policy) {
        case JDBC:
            tokenStore = new JdbcTokenStore(dataSource);
            break;
        case JWT:
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter);
            break;
        case MIX:
            JdbcTokenStore jdbcTokenStore = new JdbcTokenStore(dataSource);
            jdbcTokenStore.setAuthenticationKeyGenerator(new NoScopeAuthenticationKeyGenerator());
            tokenStore = new JWTTokenStoreDecorator(jwtAccessTokenConverter, new JwtTokenStore(jwtAccessTokenConverter),
                    jdbcTokenStore);
            break;
        default:
            assert false : "Pleaes make sure configuration for spring.oauth2.token-store-policy should be line in JDBC, JWT, MIX";
        }
        return tokenStore;
        
    }
    
    
    /**
     * @param principal the currently authentication principal
     * @return a client id if there is one in the principal
     */
    protected String getClientId(Principal principal) {
        Authentication client = (Authentication) principal;
        if (!client.isAuthenticated()) {
            throw new InsufficientAuthenticationException("The client is not authenticated.");
        }
        String clientId = client.getName();
        if (client instanceof OAuth2Authentication) {
            // Might be a client and user combined authentication
            clientId = ((OAuth2Authentication) client).getOAuth2Request().getClientId();
        }
        return clientId;
    }


    @Override
    public void afterPropertiesSet() throws Exception {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }
    
}
