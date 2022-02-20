package me.sungbin.demospringsecurityform.account;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : AccountControllerTest
 * author : rovert
 * date : 2022/02/17
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/17       rovert         최초 생성
 */

@SpringBootTest
@AutoConfigureMockMvc
class AccountControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountService accountService;

    @Test
    @WithAnonymousUser
    @DisplayName("인덱스 페이지 접속 시, 익명으로 접속이 되는지 테스트")
    void index_anonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithUser
    @DisplayName("인덱스 페이지 접속 시, 특정한 사용자로 접속이 되는지 테스트")
    void index_user() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithAdmin
    @DisplayName("인덱스 페이지 접속 시, 관리자로 접속이 되는지 테스트")
    void index_admin() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithUser
    @DisplayName("관리자 페이지 접속 시, 특정 사용자로 접속이 불가하는지 테스트")
    void admin_user() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithAdmin
    @DisplayName("관리자 페이지 접속 시, 관리자로 접속이 되는지 테스트")
    void admin_admin() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @Transactional
    @DisplayName("로그인이 잘 작동이 되는지 폼인증 확인")
    void login_success() throws Exception {
        String username = "sungbin";
        String password = "123";
        Account user = this.createUser(username, password);

        mockMvc.perform(formLogin().user(username).password(password))
                .andDo(print())
                .andExpect(authenticated());
    }

    @Test
    @Transactional
    @DisplayName("로그인을 실패하는 경우")
    void login_fail() throws Exception {
        String username = "sungbin";
        String password = "123";
        Account account =this.createUser(username, password);

        mockMvc.perform(formLogin().user(username).password("12345"))
                .andDo(print())
                .andExpect(unauthenticated());
    }

    private Account createUser(String username, String password) {
        Account account = Account.builder()
                .username(username)
                .password(password)
                .role("USER")
                .build();

        return accountService.createNew(account);
    }
}