package me.sungbin.demospringsecurityform.account;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : SignUpController
 * author : rovert
 * date : 2022/02/28
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/28       rovert         최초 생성
 */

@Controller
@RequestMapping("/signup")
@RequiredArgsConstructor
public class SignUpController {

    private final AccountService accountService;

    @GetMapping
    public String signupForm(Model model) {
        model.addAttribute("account", new Account());

        return "signup";
    }

    @PostMapping
    public String processSignUp(Account account) {
        account.setRole("USER");
        accountService.createNew(account);

        return "redirect:/";
    }
}
