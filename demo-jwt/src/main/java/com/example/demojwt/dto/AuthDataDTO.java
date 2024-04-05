package com.example.demojwt.dto;

import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthDataDTO {
     String username;
     String password;
}