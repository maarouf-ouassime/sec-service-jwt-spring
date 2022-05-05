package com.example.secservice.sec.repo;

import com.example.secservice.sec.entities.AppRole;
import com.example.secservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {

    AppRole findByRoleName(String roleName);
}
