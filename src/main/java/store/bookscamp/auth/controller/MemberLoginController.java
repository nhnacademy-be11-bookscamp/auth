package store.bookscamp.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import store.bookscamp.auth.controller.request.MemberLoginRequest;
import store.bookscamp.auth.service.MemberLoginService;
import store.bookscamp.auth.service.dto.MemberLoginDto;

@RequiredArgsConstructor
@RestController
public class MemberLoginController {

    private final MemberLoginService memberLoginService;

    @PostMapping("/login")
    public ResponseEntity<String> doLogin(@Valid @RequestBody MemberLoginRequest request){
        MemberLoginDto memberLoginDto = request.toDto(request);
        memberLoginService.doLogin(memberLoginDto);
        return new ResponseEntity<>("success", HttpStatus.OK);
    }

}
