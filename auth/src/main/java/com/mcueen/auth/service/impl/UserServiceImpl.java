package com.mcueen.auth.service.impl;

import com.mcueen.auth.config.security.UserDetailsModel;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(username);
        return user.map(UserDetailsModel::new).orElseThrow(()->new UsernameNotFoundException("User not found"));
    }
}
