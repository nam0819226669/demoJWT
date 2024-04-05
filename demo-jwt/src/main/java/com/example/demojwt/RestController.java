package com.example.demojwt;

import javax.validation.Valid;

import com.example.demojwt.jwt.JwtTokenProvider;
import com.example.demojwt.payload.LoginRequest;
import com.example.demojwt.payload.LoginResponse;
import com.example.demojwt.user.CustomUserDetails;
import com.example.demojwt.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Objects;


@org.springframework.web.bind.annotation.RestController
@RequestMapping("/api")
public class RestController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private UserService userService;

    @PostMapping("/login")
    public LoginResponse authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken((CustomUserDetails) authentication.getPrincipal());
        return new LoginResponse(jwt);
    }

    @GetMapping("/random")
    public ResponseEntity randomStuff(){
        return new ResponseEntity<>("Thành công", HttpStatus.OK);
    }

    @GetMapping("/getUser")
    public ResponseEntity randomStuff(@RequestBody String userName){
        UserDetails user = userService.loadUserByUsername(userName);
        if (Objects.isNull(user)){
            return new ResponseEntity<>("Tài khoản không tồn tại", HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>("Thành công", HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(){
        return new ResponseEntity<>("Thành công", HttpStatus.OK);
    }

}