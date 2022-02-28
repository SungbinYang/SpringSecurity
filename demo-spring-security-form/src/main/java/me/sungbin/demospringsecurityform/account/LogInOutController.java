package me.sungbin.demospringsecurityform.account;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : LogInOutController
 * author : rovert
 * date : 2022/02/28
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/28       rovert         최초 생성
 */

@Controller
public class LogInOutController {

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }

    @GetMapping("/logout")
    public String logoutForm() {
        return "logout";
    }
}
