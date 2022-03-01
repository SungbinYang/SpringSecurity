package me.sungbin.demospringsecurityform.book;

import lombok.Getter;
import lombok.Setter;
import me.sungbin.demospringsecurityform.account.Account;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

/**
 * packageName : me.sungbin.demospringsecurityform.book
 * fileName : Book
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

@Entity
@Getter
@Setter
public class Book {

    @Id @GeneratedValue
    private Integer id;

    private String title;

    @ManyToOne
    private Account author;
}
