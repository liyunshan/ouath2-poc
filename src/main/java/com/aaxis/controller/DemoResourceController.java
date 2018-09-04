package com.aaxis.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
/**
 * Created by JavaDeveloperZone on 19-07-2017.
 */
@RestController
public class DemoResourceController {
    @RequestMapping("/demo")
    public String demo(Principal principal) {
        return "Hello "+principal.getName()+", Auth 2.0 Resource Server, Access Granted by authentication server..";
    }
}