package me.sungbin.demospringsecurityform.account;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : AccessDeniedController
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

@Controller
public class AccessDeniedController {

    @GetMapping("/access-denied")
    public String accessDenied(Model model, Principal principal) {
        model.addAttribute("name", principal.getName());

        return "access-denied";
    }
}
