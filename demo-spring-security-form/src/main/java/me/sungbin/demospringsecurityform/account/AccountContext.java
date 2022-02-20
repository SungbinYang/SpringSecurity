package me.sungbin.demospringsecurityform.account;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : AccountContext
 * author : rovert
 * date : 2022/02/20
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/20       rovert         최초 생성
 */

public class AccountContext {

    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }

    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}
