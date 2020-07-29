package io.security.corespringsecurity.controller.admin;


import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class AdminController {

    @GetMapping(value="/admin")
    public String home() throws Exception {
        return "admin/home";
    }

    @GetMapping(value = "/api/admin/user")
    @ResponseBody
    public String getPrincipal(Principal principal, Authentication authentication){
        String name = principal.getName();
        return name;
    }

}
