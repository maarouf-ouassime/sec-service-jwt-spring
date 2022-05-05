package com.example.secservice.sec.service;

import com.example.secservice.sec.entities.AppRole;
import com.example.secservice.sec.entities.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String userName,String roleName);
    AppUser loadUserByUsername(String userName);
    List<AppUser> listUsers();
}
