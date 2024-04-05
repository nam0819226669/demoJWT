//package com.example.demojwt;
//
//
//import com.example.demojwt.user.User;
//import com.example.demojwt.user.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//
//@SpringBootApplication
//
//public class App1 implements CommandLineRunner {
//    public static void main(String[] args) {
//        SpringApplication.run(App.class, args);
//    }
//
//    @Autowired
//    UserRepository userRepository;
//    @Autowired
//    PasswordEncoder passwordEncoder;
//
//    @Override
//    public void run(String... args) throws Exception {
//        User user = new User();
//        user.setUsername("lodaa");
//        user.setPassword(passwordEncoder.encode("lodaa"));
//        userRepository.save(user);
//    }
//}
