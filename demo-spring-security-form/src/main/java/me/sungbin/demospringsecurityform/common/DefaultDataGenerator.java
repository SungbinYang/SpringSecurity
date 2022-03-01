package me.sungbin.demospringsecurityform.common;

import lombok.RequiredArgsConstructor;
import me.sungbin.demospringsecurityform.account.Account;
import me.sungbin.demospringsecurityform.account.AccountService;
import me.sungbin.demospringsecurityform.book.Book;
import me.sungbin.demospringsecurityform.book.BookRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * packageName : me.sungbin.demospringsecurityform.common
 * fileName : DefaultDataGenerator
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

@Component
@RequiredArgsConstructor
public class DefaultDataGenerator implements ApplicationRunner {

    private final AccountService accountService;

    private final BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Account sungbin = createUser("sungbin");
        Account robert = createUser("robert");

        createBook("spring", sungbin);
        createBook("hibernate", robert);

    }

    private void createBook(String title, Account sungbin) {
        Book book = new Book();
        book.setTitle(title);
        book.setAuthor(sungbin);
        bookRepository.save(book);
    }

    private Account createUser(String name) {
        Account account = new Account();
        account.setUsername(name);
        account.setPassword("123");
        account.setRole("USER");

        return accountService.createNew(account);
    }
}
