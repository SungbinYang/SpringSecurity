package me.sungbin.demospringsecurityform.account;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : AccountController
 * author : rovert
 * date : 2022/02/17
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/17       rovert         최초 생성
 */

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    @GetMapping("/account/{role}/{username}/{password}")
    public Account createAccount(Account account) {
        return accountService.createNew(account);
    }
}
