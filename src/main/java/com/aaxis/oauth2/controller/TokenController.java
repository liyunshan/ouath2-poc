package com.aaxis.oauth2.controller;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.aaxis.oauth2.token.TokenManager;

@FrameworkEndpoint
public class TokenController {

    @Autowired
    private TokenManager tokenManager;
    
    @RequestMapping(method = RequestMethod.DELETE, value = "/oauth/token")
    @ResponseBody
    public void revokeToken(Principal principal, HttpServletRequest request) {
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        
        this.tokenManager.removeToken(principal, username, password);
        return ;
    }
}
