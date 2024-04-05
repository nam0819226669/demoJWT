package com.example.demojwt.dto;

import lombok.*;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthDTO {
    String token;

    String refreshToken;

    AuthDataDTO data;
}