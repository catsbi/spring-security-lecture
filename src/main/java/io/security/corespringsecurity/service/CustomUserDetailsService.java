package io.security.corespringsecurity.service;


import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service("userDetailsService")
@Transactional
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				//DB에서 Account객체 조회
        Account account = userRepository.findByUsername(username);
        if(Objects.isNull(account)){
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }
				// 권한 정보 등록
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));
				
				//AccountContext 생성자로 UserDetails 타입 생성
        AccountContext accountContext = new AccountContext(account, roles);

        return  accountContext;
    }

}
