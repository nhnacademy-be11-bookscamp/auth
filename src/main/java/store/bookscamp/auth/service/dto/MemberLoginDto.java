package store.bookscamp.auth.service.dto;

import store.bookscamp.auth.entity.Member;

public record MemberLoginDto(
        String username,
        String password
) {
    public static MemberLoginDto fromEntity(Member member){
        return new MemberLoginDto(member.getUsername(),
                member.getPassword()
        );
    }
}
