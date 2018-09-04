package org.springframework.security.oauth2.provider.token.store;

import java.util.Collection;
import java.util.Map;

import org.springframework.beans.BeanUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * Decorator JWTTokenStore and add JDBC token store feature.
 * @author samli
 *
 */
@Slf4j
public class JWTTokenStoreDecorator implements TokenStore {
    
    private JwtTokenStore base;
    
    private TokenStore newFeature;

    private JwtAccessTokenConverter jwtTokenEnhancer;
    
    
    public JWTTokenStoreDecorator (JwtAccessTokenConverter jwtTokenEnhancer, JwtTokenStore base, TokenStore newFeature) {
        this.base = base;
        this.newFeature = newFeature;
        this.jwtTokenEnhancer = jwtTokenEnhancer;
    }
    

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        String jti = getTokenValue(token);
        if (StringUtils.isEmpty(jti)) {
            log.debug("return null cause jti is empty");
            return null;
        }
        return this.newFeature.readAuthentication(jti);
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
         Map tokenMap =  this.jwtTokenEnhancer.decode(token);
         if (null == tokenMap) {
             log.debug("return null cause tokenMap is null");
             return null;
         }
         String jti = (String)tokenMap.get(AccessTokenConverter.JTI);
         if (StringUtils.isEmpty(jti)) {
             log.debug("return null cause jti is empty");
             return null;
         }
         return this.newFeature.readAuthentication(jti);
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        OAuth2AccessToken existToken =  this.newFeature.getAccessToken(authentication);
        if (null != existToken) {
            OAuth2RefreshToken existRefreshToken = existToken.getRefreshToken();
            if (null != existRefreshToken) {
                this.newFeature.removeRefreshToken(existRefreshToken);
            }
            this.newFeature.removeAccessToken(existToken);
        }
        
        String jti = getTokenValue(token);
        if (StringUtils.isEmpty(jti)) {
            log.debug("return cause jti is empty");
            return;
        }
        DefaultOAuth2AccessToken persistToken = new DefaultOAuth2AccessToken(token);
        // reset jti 
        persistToken.setValue(jti);
        // reset refersh token.
        if (null != persistToken.getRefreshToken()) {
            String encodedRefreshTokenValue = persistToken.getRefreshToken().getValue();
            OAuth2AccessToken encodedRefershToken = jwtTokenEnhancer.extractAccessToken(encodedRefreshTokenValue,
                    jwtTokenEnhancer.decode(encodedRefreshTokenValue));
            String refershTokenValue = getTokenValue(encodedRefershToken);
            DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refershTokenValue);
            persistToken.setRefreshToken(refreshToken);
        }
        this.newFeature.storeAccessToken(persistToken, authentication);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        return base.readAccessToken(tokenValue);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        String jti = getTokenValue(token);
        if (StringUtils.isEmpty(jti)) {
            log.debug("return cause jti is empty");
            return;
        }
        DefaultOAuth2AccessToken removeToken = new DefaultOAuth2AccessToken(jti);
        BeanUtils.copyProperties(token, removeToken, "value");
        this.newFeature.removeAccessToken(removeToken);
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken encodedRefreshToken, OAuth2Authentication authentication) {
        String encodedRefreshTokenValue = encodedRefreshToken.getValue();
        OAuth2AccessToken encodedRefershToken = jwtTokenEnhancer.extractAccessToken(encodedRefreshTokenValue,
                jwtTokenEnhancer.decode(encodedRefreshTokenValue));
        String refershTokenValue = getTokenValue(encodedRefershToken);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refershTokenValue);
        this.newFeature.storeRefreshToken(refreshToken, authentication);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        return this.base.readRefreshToken(tokenValue);
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken encodedRefreshToken) {
        String encodedRefreshTokenValue = encodedRefreshToken.getValue();
        OAuth2AccessToken encodedRefershToken = jwtTokenEnhancer.extractAccessToken(encodedRefreshTokenValue,
                jwtTokenEnhancer.decode(encodedRefreshTokenValue));
        String refershTokenValue = getTokenValue(encodedRefershToken);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refershTokenValue);
        OAuth2Authentication authentication = this.newFeature.readAuthenticationForRefreshToken(refreshToken);
        if (authentication == null) {
            throw new InvalidGrantException("Invalid refresh token: " + encodedRefreshToken.getValue());
        }
        return authentication;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken encodedRefreshToken) {
        this.base.removeRefreshToken(encodedRefreshToken);
        String encodedRefreshTokenValue = encodedRefreshToken.getValue();
        OAuth2AccessToken encodedRefershToken = jwtTokenEnhancer.extractAccessToken(encodedRefreshTokenValue,
                jwtTokenEnhancer.decode(encodedRefreshTokenValue));
        String refershTokenValue = getTokenValue(encodedRefershToken);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refershTokenValue);
        this.newFeature.removeRefreshToken(refreshToken);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken encodedRefreshToken) {
        String encodedRefreshTokenValue = encodedRefreshToken.getValue();
        OAuth2AccessToken encodedRefershToken = jwtTokenEnhancer.extractAccessToken(encodedRefreshTokenValue,
                jwtTokenEnhancer.decode(encodedRefreshTokenValue));
        String refershTokenValue = getTokenValue(encodedRefershToken);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refershTokenValue);
        this.newFeature.removeAccessTokenUsingRefreshToken(refreshToken);

    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return this.base.getAccessToken(authentication);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        return this.base.findTokensByClientIdAndUserName(clientId, userName);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        return this.base.findTokensByClientId(clientId);
    }
    
    protected String getTokenValue(OAuth2AccessToken token) {
        if(null == token || null == token.getAdditionalInformation() ) {
            log.debug("return null cause token is null or AdditionalInformation is null, {}", token);
            return null;
        }
        String jti = (String)token.getAdditionalInformation().get(AccessTokenConverter.JTI);
        if (StringUtils.isEmpty(jti)) {
            log.debug("return null cause jti is empty");
            return null;
        }
        return jti;
    }

}
