package com.example.demojwt.token;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "tokenUser")
@Setter
@Getter
@Data
public class Token {
    @Id
    @GeneratedValue
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;
    private String token;
    private int status;
}
