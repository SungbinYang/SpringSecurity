package me.sungbin.demospringsecurityform.account;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : AccountRepository
 * author : rovert
 * date : 2022/02/17
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/17       rovert         최초 생성
 */

public interface AccountRepository extends JpaRepository<Account, Integer> {

    Account findByUsername(String username);
}
