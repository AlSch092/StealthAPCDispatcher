.data


.code

_MyNtQueueApcThreadEx PROC
    mov r10, rcx
    mov eax,166h ; this might change on your version of windows, this ordinal is for build 19045
    syscall
    ret
_MyNtQueueApcThreadEx ENDP


_MyNtQueueApcThreadEx2 PROC

    mov r10, rcx
    mov eax,167h  ; this might change on your version of windows, this ordinal is for build 19045
    syscall
    ret
_MyNtQueueApcThreadEx2 ENDP


END