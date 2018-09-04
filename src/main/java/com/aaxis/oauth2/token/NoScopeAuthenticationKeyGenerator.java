package com.aaxis.oauth2.token;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

public class NoScopeAuthenticationKeyGenerator extends DefaultAuthenticationKeyGenerator {
    
    public static final String CLIENT_ID = "client_id";

    public static final String USERNAME = "username";
    
    @Override
    public String extractKey(OAuth2Authentication authentication) {
        Map<String, String> values = new LinkedHashMap<String, String>();
        OAuth2Request authorizationRequest = authentication.getOAuth2Request();
        if (!authentication.isClientOnly()) {
            values.put(USERNAME, authentication.getName());
        }
        values.put(CLIENT_ID, authorizationRequest.getClientId());
        return generateKey(values);
    }
    
    public String getKey(Map<String, String> values) {
        return generateKey(values);
    }

}
