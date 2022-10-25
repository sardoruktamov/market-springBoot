package uz.market.backend.web.rest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import uz.market.backend.domain.User;
import uz.market.backend.service.UserService;

@RestController
@RequestMapping("/api")
public class UserResource {

    private final UserService userService;

    public UserResource(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity create(@RequestBody User user){

        // royxatdan o'tishda avvaldan login bo'lsa TRUE qaytaradi va biz ERROR qaytaramiz
        if (userService.existsByLogin(user.getUserName())){
            return new ResponseEntity("Bu Login Mavjud!", HttpStatus.BAD_REQUEST);
        }

        if (checkPasswordLength(user.getPassword())){
            return new ResponseEntity("Parol 4 tadan kam!", HttpStatus.BAD_REQUEST);
        }

        User result = userService.save(user);
        return ResponseEntity.ok(result);
    }

    private Boolean checkPasswordLength(String password){
        return password.length() <= 4;
    }
}