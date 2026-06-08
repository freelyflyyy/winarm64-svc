		AREA |.text|, CODE, READONLY
		EXPORT A64CallImpl


A64CallImpl PROC
			;    this is a up to 8 argument call, 
			; the arguments are passed in an array of 64-bit values
			
			; x0: function address
			; x1: argument count
			; x2: pointer to arguments array
			stp x19, x20, [sp, #-16]!
			stp x21, x30, [sp, #-16]!

			mov x19, x0
			mov x20, x1
			mov x21, x2

			adr x9, call_target
			sub x9, x9, x20, lsl #2
			br x9

			ldr x7, [x21, #56]
			ldr x6, [x21, #48]
			ldr x5, [x21, #40]
			ldr x4, [x21, #32]
			ldr x3, [x21, #24]
			ldr x2, [x21, #16]
			ldr x1, [x21, #8] 
			ldr x0, [x21]     

call_target
			blr x19

			; Restore registers
			ldp x21, x30, [sp], #16
			ldp x19, x20, [sp], #16
			ret
A64CallImpl ENDP
			END