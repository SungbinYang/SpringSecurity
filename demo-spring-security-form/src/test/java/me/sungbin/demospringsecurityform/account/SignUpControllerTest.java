package me.sungbin.demospringsecurityform.account;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.core.StringContains.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : SignUpControllerTest
 * author : rovert
 * date : 2022/02/28
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/28       rovert         최초 생성
 */

@SpringBootTest
@AutoConfigureMockMvc
class SignUpControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @DisplayName("signup 폼으로 보여주는 테스트")
    void signupForm() throws Exception {
        this.mockMvc.perform(get("/signup"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")));
    }

    @Test
    @DisplayName("폼 서브밋 테스트")
    void processSignUp() throws Exception {
        this.mockMvc.perform(post("/signup")
                        .param("username", "robert")
                        .param("password", "123")
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection());
    }
}