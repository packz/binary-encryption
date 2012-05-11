; burneye initialization function

	GLOBAL	be_entry

	EXTERN	burneye

; this is the central entry point of the program
; we have to take care about not destorying the kernel supplied auxv's
;

; WARNING: this code is quite unclean, you do not want to mess with it, really

be_entry:
	pushf

	; ebx = addr, ecx = len, edx = prot
;	mov	ebx, 0x05370000	; addr
;	mov	edx, 0x0007	; PROT_READ | PROT_WRITE | PROT_EXEC
;	mov	ecx, be_payload
;	mov	ecx, 0x0000b000
;	sub	ecx, 0x05371000

;	mov	eax, 0x7d	; __NR_mprotect
;	int	0x80

	pop	ebx

	mov	esi, esp
	call	be_auxv		; ecx = number of vectors, edx = base
	mov	ebp, edx	; base of auxv

	cmp	ecx, 32		; more than 32 vectors
	jl	rel_auxv	;   not enough -> relocate

	xor	eax, eax
	jmp	do_auxv

	; we need eax more vectors
rel_auxv:
	mov	eax, 32
	sub	eax, ecx
	shl	eax, 3		; * 8

do_auxv:
	mov	esi, esp
	sub	esp, eax
	mov	edi, esp
	sub	ebp, eax

	; relocate auxiliary vectors
	call	be_auxvreloc	; in: esi = &argc ; out: edx = env[0]

	pop	eax		; eax = argc
	push	eax
	push	ebx		; SAVE flag register

	push	eax		; argc
	mov	eax, esp
	add	eax, 12		; &argv[0]
	push	eax

	push	edx		; env
	push	ebp		; lowest vector
	push	ecx		; number of real vectors, space is for 32
	call	burneye		; returns: eax = entry point of rtld/exe
	add	esp, (5 * 4)

	pop	ebx		; RESTORE flag register
	push	eax		; save entry point on stack, to 'ret' to

	; make an 'oops... i did it again' virgin stack space
%define	BRITNEY	1024
        lea	edi, [esp - 4 * BRITNEY]
        pusha
	sub	esp, (BRITNEY * 4)
        mov	ecx, BRITNEY
        xor	eax, eax
        rep	stosd		; zap array
	add	esp, (BRITNEY * 4)

	; thanks to john reiser <jreister@bitwagon.com> for fixing this nasty
	; bug :-)
	push	ebx		; i hate x86 register poorness
	popf			; restore original flags
	push	dword 0		; clear stack element
	pop	ebx


%ifdef VDEBUG
	int3			; FINAL BREAKPOINT
%endif

	popa			; all regs except eip/esp are zero'ed now
	ret			; return to entry point of ld-linux.so.*


; be_auxvreloc, insert 
;
; in: esi = source &argc, edi = dest
; out: edi = &old_auxv[AT_NULL]
;

be_auxvreloc:
rarg:	lodsd
	stosd
	or	eax, eax
	jnz	be_auxvreloc

	mov	edx, edi	; new &env[0]
renv:	lodsd
	stosd
	or	eax, eax
	jnz	renv

raux:	lodsd
	stosd
	or	eax, eax
	lodsd
	stosd
	jnz	raux

	sub	edi, 8
	ret

; be_auxv, find and count aux vectors
;
; stack looks like (at esi);
; <argc> <argc pointers> <NULL> <env[0], env[1], ...> <NULL> <aux> <env>
be_auxv:
	; skip arguments
	lodsd
	shl	eax, 2
	add	eax, 4
	add	esi, eax

	; skip environment
skenv:	lodsd
	or	eax, eax
	jnz	skenv

	xor	ecx, ecx	; counter = 0
	mov	edx, esi	; &auxv[0]
skaux:	lodsd
	inc	ecx
	or	eax, eax
	lodsd
	jnz	skaux

	; we have ecx vectors now, INCLUDING the AT_NULL vector
	ret

; be_findenv, find environment pointer array
;
; esi = pointer to lowest vector
;
; return: esi = env[0]
;

