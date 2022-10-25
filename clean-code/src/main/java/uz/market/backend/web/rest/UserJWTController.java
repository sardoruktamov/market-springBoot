package uz.market.backend.web.rest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import uz.market.backend.domain.User;
import uz.market.backend.repository.UserRepository;
import uz.market.backend.security.JwtTokenProvider;
import uz.market.backend.web.rest.vm.LoginVM;

import java.util.HashMap;
import java.util.Map;

// jwt 7-qadam fayl yaratamiz..
@RestController
@RequestMapping("api")
public class UserJWTController {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    public UserJWTController(JwtTokenProvider jwtTokenProvider, AuthenticationManager authenticationManager, UserRepository userRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
    }

    // jwt 9-qadam
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginVM loginVM){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword()));
        User user = userRepository.findByLogin(loginVM.getUsername());

        if(user == null) {
            throw new UsernameNotFoundException("Bu foydalanuvchi mavjud emas!");
        }
        // endigi navbat JWT yasaymiz
        String token = jwtTokenProvider.createToken(user.getUserName(), (Authentication) user.getRoles());
        Map<Object, Object> map = new HashMap<>();
        map.put("username", user.getUserName());
        map.put("token", token);
        return ResponseEntity.ok(map);
    }

    //JWT 11-qadam
    static class JWTToken{
        private String idToken;

        public String getIdToken() {
            return idToken;
        }

        public void setIdToken(String idToken) {
            this.idToken = idToken;
        }

        public JWTToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
