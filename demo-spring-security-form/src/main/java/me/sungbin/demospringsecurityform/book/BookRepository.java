package me.sungbin.demospringsecurityform.book;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

/**
 * packageName : me.sungbin.demospringsecurityform.book
 * fileName : BookRepository
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

public interface BookRepository extends JpaRepository<Book, Integer> {

    @Query("select b from Book b where b.author.id = ?#{principal.account.id}")
    List<Book> findCurrentUserBook();
}
