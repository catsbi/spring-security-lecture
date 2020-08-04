package io.security.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopMethodService {

    public void methodSecured(){
        System.out.println("methodSecured");
    }

    public String getPath(){
        return this.getClass().getName();
    }

}
