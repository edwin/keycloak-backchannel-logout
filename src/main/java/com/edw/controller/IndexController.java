package com.edw.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.HashMap;

/**
 * <pre>
 *     com.edw.controller.IndexController
 * </pre>
 *
 * @author Muhammad Edwin < edwin at redhat dot com >
 * 26 Sep 2022 21:22
 */
@RestController
public class IndexController {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping(path = "/")
    public HashMap index(KeycloakAuthenticationToken authentication, HttpSession httpSession) {
        SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
        AccessToken token = account.getKeycloakSecurityContext().getToken();
        httpSession.setAttribute(token.getSessionId(), account.getKeycloakSecurityContext().getTokenString());

        return new HashMap(){{
            put("hello", token.getPreferredUsername());
        }};
    }

    @PostMapping(path = "/sso-logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public HashMap logout(@RequestParam("logout_token") String logoutToken) throws Exception {

        String[] splitString = logoutToken.split("\\.");
        String body = new String(java.util.Base64.getDecoder().decode(splitString[1]));

        ObjectMapper mapper = new ObjectMapper();
        HashMap bodyMap = mapper.readValue(body, HashMap.class);

        logger.debug("logging out {}", bodyMap.get("sid"));

        jdbcTemplate.update("DELETE FROM `spring_session` " +
                "WHERE `PRIMARY_ID` = (SELECT `PRIMARY_ID` FROM `spring_session_attributes` WHERE `ATTRIBUTE_NAME` = ?)",
                new Object[] { bodyMap.get("sid") });

        return new HashMap(){{
            put("status", true);
        }};
    }
}
