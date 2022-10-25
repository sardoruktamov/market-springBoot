package uz.market.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    //  JWTtoken 2-qadam buil.gradle faylida
    //  JWTtoken 3-qadam
    @Value("${jwt.token.secret}")
    private String secret;

    @Value("${jwt.token.validity}")
    private Long validityMilliSecond;

    private final UserDetailsService userDetailsService;

    public JwtTokenProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    // secret kalitimizni baytcodega o`tkazib olish (xavfsizlikni kuchaytirish)
    @PostConstruct
    protected void init(){
        this.secret = Base64.getEncoder().encodeToString(secret.getBytes());
    }

    //  JWTtoken 10-qadam
    public String createToken(String username, Authentication authentication){
        // authentication ichidan role ni ajratib olish
        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        // JWTga solinishi kk bolgan malumotlar solindi(username va rules)
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);   // qoshimchasiga bu yerda userga tegishli barcha narsani kiritish mn
        // tokenni yashash muddatini qoyish
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityMilliSecond); //hozirgi vaqtdan boshlab 1 kun

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, this.secret)   // HS256 algoritm boyicha shirflashni belgilash
                .compact();

    }

    //spring 46-dars 2.00
    public Authentication getAuthentication(String token){
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails,"",userDetails.getAuthorities());
    }
    // kelayotgan tokendan usernameni olish
    private String getUsername(String token){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
    }

    //spring 45-dars 8.00 tokenni muddatini tekshirish
    public boolean validateToken(String token){
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
            if (claimsJws.getBody().getExpiration().before(new Date())){
                return false;
            }
        }catch (IllegalArgumentException e){
            e.printStackTrace();
        }
        return true;
    }

    // parolni encode qilish (JWTtoken 6-qadam)
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    public String resolveToken(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }

}
