# Reconstructed BN254 genpow leader assembly. Stack order: bottom to top.
# Baseline artifact 61c451d0bf8835e6ab850a02c325775d3769dbff92b87ba2d564c8f1f8494c83.
# Outline names preserve exact low-level programs; unproved high-level identities are not asserted.

function fp_add 8
OP_ADD
call reduce_mod_p
end

function fp_sub_top_minus_next 4
OP_SWAP
OP_SUB
call prime
OP_SWAP
OP_OVER
OP_ADD
OP_SWAP
OP_MOD
end

function fp_mul 1
OP_MUL
call reduce_mod_p
end

function outline_35 35
call prime
OP_DUP
OP_ROT
OP_SUB
OP_SWAP
OP_MOD
end

function outline_6 6
OP_ROT
OP_SWAP
call fp_add
OP_ROT
OP_ROT
call fp_add
end

function outline_3 3
OP_ROT
OP_SWAP
call fp_sub_top_minus_next
OP_ROT
OP_ROT
call fp_sub_top_minus_next
end

function outline_22 22
OP_0
call fp_sub_top_minus_next
OP_SWAP
OP_0
call fp_sub_top_minus_next
end

function fp2_mul 2
OP_3
OP_PICK
OP_2
OP_PICK
call fp_mul
OP_3
OP_PICK
OP_2
OP_PICK
call fp_mul
call fp_sub_top_minus_next
OP_2SWAP
call fp_mul
OP_2SWAP
call fp_mul
call fp_add
end

function outline_5 5
OP_2DUP
OP_2OVER
call fp2_mul
OP_ROT
OP_DROP
OP_ROT
OP_DROP
end

function outline_23 23
OP_2DUP
OP_9
call fp_mul
call fp_sub_top_minus_next
OP_SWAP
OP_ROT
OP_9
call fp_mul
call fp_add
end

function outline_17 17
OP_2
OP_PICK
OP_SWAP
call fp_mul
OP_ROT
OP_ROT
call fp_mul
end

function outline_9 9
OP_2
OP_PICK
OP_SWAP
call fp_mul
OP_ROT
OP_ROT
call fp_mul
end

function outline_36 36
push a47e3e6c0b46109e46e538b448b5c0cb2eacc040db2228dc14d0987039273218
OP_DUP
OP_ROT
call fp_mul
OP_SWAP
OP_ROT
call fp_mul
end

function outline_18 18
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_2SWAP
call outline_6
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_2ROT
call outline_6
call outline_59
call outline_6
end

function outline_37 37
OP_2ROT
call outline_23
OP_2SWAP
OP_SWAP
OP_2ROT
OP_SWAP
end

function outline_28 28
OP_9
OP_PICK
OP_9
OP_PICK
OP_7
OP_PICK
OP_7
OP_PICK
call fp2_mul
OP_13
OP_PICK
OP_13
OP_PICK
OP_7
OP_PICK
OP_7
OP_PICK
call fp2_mul
call outline_16
OP_SWAP
call outline_23
OP_9
OP_PICK
OP_9
OP_PICK
OP_5
OP_PICK
OP_5
OP_PICK
call fp2_mul
call outline_16
OP_13
OP_PICK
OP_13
OP_PICK
OP_9
OP_PICK
OP_9
OP_PICK
call fp2_mul
OP_SWAP
call outline_23
OP_11
OP_PICK
OP_11
OP_PICK
OP_9
OP_PICK
OP_9
OP_PICK
call fp2_mul
OP_15
OP_PICK
OP_15
OP_PICK
OP_9
OP_PICK
OP_9
OP_PICK
call fp2_mul
call outline_16
call outline_16
call outline_10
call fp2_mul
call outline_10
call fp2_mul
call outline_10
call fp2_mul
call outline_16
call outline_16
end

function outline_38 38
OP_7
OP_PICK
OP_7
OP_PICK
OP_2OVER
call fp2_mul
OP_11
OP_PICK
OP_11
OP_PICK
OP_7
OP_PICK
OP_7
OP_PICK
call fp2_mul
OP_9
OP_PICK
OP_9
OP_PICK
OP_9
OP_PICK
OP_9
OP_PICK
call outline_6
OP_15
OP_PICK
OP_15
OP_PICK
OP_2SWAP
OP_SWAP
call fp2_mul
OP_2OVER
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
OP_SWAP
call outline_23
OP_4
OP_PICK
OP_6
OP_PICK
OP_2SWAP
OP_SWAP
call outline_6
OP_15
OP_ROLL
OP_15
OP_ROLL
OP_15
OP_PICK
OP_15
OP_PICK
call outline_6
OP_11
OP_ROLL
OP_11
OP_ROLL
OP_11
OP_PICK
OP_11
OP_PICK
call outline_6
OP_SWAP
OP_2SWAP
OP_SWAP
call fp2_mul
OP_6
OP_PICK
OP_8
OP_PICK
OP_2SWAP
OP_SWAP
call outline_3
OP_4
OP_PICK
OP_6
OP_PICK
OP_2SWAP
OP_SWAP
call outline_3
call outline_10
call outline_6
OP_11
OP_ROLL
OP_11
OP_ROLL
OP_2SWAP
OP_SWAP
call fp2_mul
OP_8
OP_ROLL
OP_9
OP_ROLL
OP_2SWAP
OP_SWAP
call outline_3
OP_6
OP_ROLL
OP_7
OP_ROLL
OP_2SWAP
OP_SWAP
call outline_6
end

function outline_29 29
call outline_44
call outline_14
call outline_37
call outline_44
call outline_7
call outline_7
call outline_18
call outline_13
call outline_13
call outline_28
call outline_13
call outline_13
call outline_28
call outline_7
call outline_7
call outline_18
end

function outline_39 39
call outline_11
call outline_11
call outline_11
call outline_13
call outline_13
call outline_29
end

function outline_30 30
OP_5
OP_PICK
OP_5
OP_PICK
call outline_61
OP_7
OP_PICK
OP_7
OP_PICK
call outline_61
OP_11
OP_ROLL
OP_11
OP_ROLL
OP_4
OP_PICK
OP_6
OP_PICK
call fp2_mul
OP_13
OP_ROLL
OP_13
OP_ROLL
OP_4
OP_PICK
OP_6
OP_PICK
call fp2_mul
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
OP_4
OP_PICK
OP_6
OP_PICK
call outline_22
OP_5
OP_PICK
OP_5
OP_PICK
OP_6
OP_PICK
OP_8
OP_PICK
call outline_5
OP_8
OP_PICK
OP_10
OP_PICK
OP_2OVER
OP_SWAP
call fp2_mul
OP_15
OP_ROLL
OP_15
OP_ROLL
OP_2ROT
OP_SWAP
call fp2_mul
OP_2
OP_OVER
OP_3
OP_PICK
call outline_17
OP_SWAP
OP_4
OP_PICK
OP_6
OP_PICK
call outline_3
OP_14
OP_PICK
OP_16
OP_PICK
call outline_5
push 15
OP_PICK
push 15
OP_PICK
OP_2SWAP
OP_SWAP
call fp2_mul
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_6
OP_2DUP
OP_SWAP
OP_14
OP_ROLL
OP_15
OP_ROLL
call fp2_mul
OP_2SWAP
OP_SWAP
OP_2ROT
OP_SWAP
call outline_3
OP_12
OP_ROLL
OP_13
OP_ROLL
OP_2SWAP
OP_SWAP
call fp2_mul
OP_13
OP_ROLL
OP_13
OP_ROLL
OP_6
OP_PICK
OP_8
OP_PICK
call fp2_mul
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
OP_2ROT
OP_SWAP
OP_13
OP_ROLL
OP_13
OP_ROLL
call fp2_mul
call outline_21
end

function outline_24 24
push 12
OP_PICK
OP_15
OP_ROLL
call fp_mul
push 12
OP_ROLL
OP_16
OP_ROLL
call fp_mul
push 12
OP_PICK
push 11
OP_ROLL
call fp_mul
push 12
OP_ROLL
push 12
OP_ROLL
call fp_mul
push 11
OP_ROLL
push 11
OP_ROLL
OP_4
OP_ROLL
OP_5
OP_ROLL
OP_4
OP_ROLL
OP_5
OP_ROLL
call outline_15
call outline_15
call outline_15
call outline_15
call outline_11
call outline_11
call outline_11
call outline_18
push 13
OP_PICK
push 13
OP_PICK
OP_9
OP_ROLL
OP_9
OP_ROLL
call fp2_mul
push 13
OP_PICK
push 13
OP_PICK
OP_11
OP_ROLL
OP_11
OP_ROLL
call fp2_mul
push 13
OP_PICK
push 13
OP_PICK
OP_13
OP_ROLL
OP_13
OP_ROLL
call fp2_mul
push 15
OP_PICK
push 15
OP_PICK
push 15
OP_ROLL
push 15
OP_ROLL
call outline_6
push 17
OP_PICK
push 17
OP_PICK
OP_ROT
OP_3
OP_ROLL
OP_10
OP_ROLL
OP_11
OP_ROLL
call outline_60
call outline_38
call outline_53
call outline_53
call outline_53
push 15
OP_ROLL
call outline_38
OP_DUP
OP_2
OP_PICK
OP_4
OP_PICK
OP_6
OP_PICK
OP_8
OP_PICK
OP_10
OP_PICK
call outline_37
push 12
OP_PICK
call outline_52
push 1a
OP_PICK
push 1c
OP_PICK
call outline_7
call outline_18
call outline_7
call outline_51
call outline_18
call outline_14
call outline_60
OP_16
OP_ROLL
push 11
OP_ROLL
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_2SWAP
call outline_3
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_2ROT
call outline_3
call outline_59
call outline_3
end

function outline_31 31
OP_SWAP
call outline_35
push a2cb0f641cd56516ce9d7c0b1d2aae3294075ad78bcca44b20aeeb6150e5c916
push 3d556f175795e3990c33c3c210c38cb743b159f53cec0b4cf711794f9847b32f
OP_2SWAP
OP_SWAP
call fp2_mul
OP_2SWAP
OP_SWAP
call outline_35
push e3b02326637fd382d25ba28fc97d80212b6f79eca7b504079a0441acbc3cc007
push 5a13a071460154dc9859c9a9ede0aadbb9f9e2b698c65edcdcf59a4805f33c06
OP_2SWAP
OP_SWAP
call fp2_mul
end

function outline_40 40
call outline_62
OP_12
OP_PICK
OP_14
OP_PICK
OP_16
OP_PICK
push 12
OP_PICK
OP_1
OP_0
OP_0
OP_BEGIN
OP_DUP
push 41
OP_LESSTHAN
OP_DUP
OP_TOALTSTACK
OP_IF
call outline_14
OP_6
OP_ROLL
OP_3
OP_PICK
OP_3
OP_PICK
call outline_5
OP_7
OP_PICK
OP_7
OP_PICK
call outline_5
OP_3
OP_OVER
OP_3
OP_PICK
call outline_17
OP_SWAP
call outline_43
call fp2_mul
OP_4
OP_PICK
OP_6
OP_PICK
OP_2
OP_PICK
OP_4
OP_PICK
call outline_3
OP_9
OP_PICK
OP_9
OP_PICK
call outline_5
OP_3
OP_SWAP
OP_ROT
call outline_17
OP_15
OP_ROLL
OP_15
OP_ROLL
OP_15
OP_PICK
OP_15
OP_PICK
call outline_6
OP_SWAP
call outline_5
OP_8
OP_ROLL
OP_9
OP_ROLL
OP_ROT
OP_3
OP_ROLL
call outline_3
OP_8
OP_PICK
OP_10
OP_PICK
OP_ROT
OP_3
OP_ROLL
call outline_3
OP_DUP
OP_2
OP_PICK
call outline_22
OP_3
OP_9
OP_PICK
OP_11
OP_PICK
call outline_17
OP_DUP
OP_2
OP_PICK
OP_14
OP_PICK
OP_16
OP_PICK
call outline_3
push 11
OP_ROLL
push 11
OP_ROLL
OP_ROT
OP_3
OP_ROLL
call fp2_mul
push 11
OP_ROLL
push 11
OP_ROLL
OP_ROT
OP_3
OP_ROLL
call fp2_mul
OP_SWAP
call outline_36
OP_12
OP_ROLL
OP_13
OP_ROLL
call outline_5
OP_3
OP_SWAP
OP_ROT
call outline_17
OP_4
OP_ROLL
OP_5
OP_ROLL
OP_14
OP_PICK
OP_16
OP_PICK
call outline_6
OP_SWAP
call outline_36
OP_SWAP
call outline_5
OP_ROT
OP_3
OP_ROLL
OP_ROT
OP_3
OP_ROLL
call outline_3
OP_6
OP_ROLL
OP_7
OP_ROLL
OP_12
OP_ROLL
OP_13
OP_ROLL
call fp2_mul
OP_13
OP_ROLL
OP_14
OP_ROLL
call outline_25
push 18
OP_ROLL
call outline_39
push 1e
OP_PICK
push 1e
OP_PICK
call outline_52
push 1a
OP_PICK
push 1c
OP_PICK
push 1e
OP_PICK
call outline_56
push 8aa212a484a2442a
push 19
OP_PICK
OP_RSHIFTNUM
OP_2
OP_MOD
OP_DUP
OP_1
OP_NUMEQUAL
call outline_12
call outline_12
call outline_12
push 13
OP_ROLL
push 13
OP_ROLL
push 13
OP_ROLL
push 13
OP_ROLL
push 13
OP_ROLL
push 13
OP_ROLL
call outline_54
call outline_54
call outline_54
OP_IF
push 8222122084a04002
OP_8
OP_PICK
OP_RSHIFTNUM
OP_2
OP_MOD
push 1d
OP_PICK
push 1f
OP_PICK
OP_2
OP_PICK
OP_1
OP_NUMEQUAL
OP_IF
push 20
OP_PICK
push 20
OP_PICK
call outline_22
OP_ROT
OP_DROP
OP_ROT
OP_DROP
OP_ENDIF
OP_SWAP
push 1e
OP_PICK
push 1e
OP_PICK
OP_13
OP_ROLL
call outline_26
call outline_30
push 26
OP_PICK
push 26
OP_PICK
OP_8
OP_ROLL
call outline_20
push 17
OP_ROLL
push 18
OP_ROLL
push 19
OP_ROLL
call outline_48
call outline_24
push 12
OP_ROLL
OP_DROP
call outline_21
call outline_15
call outline_15
call outline_19
call outline_19
OP_ENDIF
OP_7
OP_ROLL
OP_1ADD
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_ENDIF
OP_FROMALTSTACK
OP_NOT
OP_UNTIL
push 16
OP_ROLL
push 16
OP_ROLL
push 16
OP_ROLL
push 16
OP_ROLL
call outline_31
OP_DUP
OP_2
OP_PICK
OP_4
OP_PICK
OP_6
OP_PICK
call outline_31
OP_SWAP
call outline_22
call outline_58
call outline_20
OP_14
OP_ROLL
call outline_30
call outline_60
call outline_58
OP_8
OP_ROLL
OP_9
OP_ROLL
call outline_30
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
push 1a
OP_PICK
push 1a
OP_PICK
OP_8
OP_ROLL
call outline_20
call outline_25
push 18
OP_ROLL
push 19
OP_ROLL
push 1a
OP_ROLL
call outline_24
push 14
OP_ROLL
push 14
OP_ROLL
call outline_26
push 13
OP_ROLL
call outline_56
OP_12
OP_ROLL
OP_DROP
call outline_21
end

function outline_41 41
OP_2DUP
call outline_5
OP_5
OP_PICK
OP_5
OP_PICK
call outline_5
OP_2DUP
OP_SWAP
call outline_5
OP_2SWAP
OP_SWAP
OP_7
OP_ROLL
OP_7
OP_ROLL
call outline_6
OP_SWAP
call outline_5
OP_4
OP_PICK
OP_6
OP_PICK
OP_2SWAP
OP_SWAP
call outline_3
OP_2OVER
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
OP_2
OP_SWAP
OP_ROT
call outline_9
OP_3
OP_5
OP_ROLL
OP_6
OP_ROLL
call outline_9
OP_2DUP
OP_SWAP
call outline_5
OP_2
OP_5
OP_PICK
OP_7
OP_PICK
call outline_9
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
OP_2DUP
OP_SWAP
OP_6
OP_ROLL
OP_7
OP_ROLL
call outline_3
OP_SWAP
OP_2ROT
OP_SWAP
call fp2_mul
OP_8
OP_5
OP_ROLL
OP_6
OP_ROLL
call outline_9
OP_SWAP
OP_2SWAP
OP_SWAP
call outline_3
call outline_59
call fp2_mul
OP_2
OP_SWAP
OP_ROT
call outline_9
end

function outline_32 32
OP_3
OP_PICK
OP_5
OP_PICK
OP_7
OP_PICK
OP_5
OP_PICK
OP_0
OP_NUMNOTEQUAL
OP_IF
OP_5
OP_PICK
OP_DUP
OP_DUP
call fp_mul
OP_NIP
OP_9
OP_PICK
OP_DUP
OP_DUP
call fp_mul
OP_NIP
OP_DUP
OP_6
OP_PICK
call fp_mul
OP_2
OP_PICK
OP_10
OP_PICK
call fp_mul
OP_2
OP_PICK
OP_13
OP_PICK
OP_10
OP_PICK
call fp_mul
call fp_mul
OP_4
OP_PICK
OP_11
OP_PICK
OP_14
OP_PICK
call fp_mul
call fp_mul
OP_2OVER
OP_NUMEQUAL
OP_2
OP_PICK
OP_2
OP_PICK
OP_NUMEQUAL
OP_BOOLAND
OP_IF
OP_9
OP_PICK
OP_10
OP_PICK
call fp_mul
OP_DUP
OP_3
call fp_mul
OP_DUP
OP_OVER
call fp_mul
OP_13
OP_PICK
OP_14
OP_PICK
call fp_mul
OP_DUP
OP_OVER
call fp_mul
OP_DUP
OP_8
call fp_mul
OP_ROT
OP_15
OP_PICK
call outline_45
OP_13
OP_PICK
OP_13
OP_PICK
call fp_mul
OP_2
call outline_49
OP_ELSE
OP_OVER
OP_OVER
call fp_sub_top_minus_next
OP_2
call fp_mul
OP_DUP
OP_OVER
call fp_mul
OP_5
OP_PICK
OP_5
OP_PICK
call fp_sub_top_minus_next
OP_DUP
OP_2
call fp_mul
OP_DUP
OP_SWAP
call fp_mul
OP_DUP
OP_2
OP_PICK
call fp_mul
OP_DUP
OP_4
OP_ROLL
call fp_sub_top_minus_next
OP_SWAP
OP_6
OP_PICK
call fp_mul
OP_2
call fp_mul
OP_ROT
OP_8
OP_PICK
call outline_57
OP_4
OP_ROLL
call fp_mul
OP_ROT
OP_SWAP
call fp_sub_top_minus_next
push 11
OP_PICK
OP_15
OP_PICK
call fp_add
OP_DUP
OP_SWAP
call fp_mul
OP_9
OP_PICK
OP_SWAP
call fp_sub_top_minus_next
OP_8
OP_PICK
OP_SWAP
call fp_sub_top_minus_next
OP_3
OP_ROLL
OP_SWAP
call outline_49
OP_ENDIF
OP_2DROP
OP_2DROP
OP_2DROP
OP_ENDIF
OP_ROT
OP_ROT
OP_2SWAP
OP_NIP
OP_3
OP_ROLL
OP_DROP
OP_3
OP_ROLL
OP_DROP
OP_3
OP_ROLL
OP_DROP
OP_3
OP_ROLL
OP_DROP
OP_3
OP_ROLL
OP_DROP
end

function outline_42 42
OP_0
OP_1
OP_0
OP_2ROT
OP_SWAP
OP_1
OP_0
OP_BEGIN
OP_DUP
push fe00
OP_LESSTHAN
OP_DUP
OP_TOALTSTACK
OP_IF
OP_7
OP_PICK
OP_OVER
OP_RSHIFTNUM
OP_2
OP_MOD
OP_1
OP_NUMEQUAL
OP_IF
OP_OVER
OP_3
OP_PICK
OP_5
OP_PICK
OP_7
OP_ROLL
OP_8
OP_ROLL
OP_9
OP_ROLL
call outline_32
OP_ROT
OP_ROT
OP_ROT
OP_6
OP_ROLL
OP_6
OP_ROLL
OP_6
OP_ROLL
OP_6
OP_ROLL
OP_ENDIF
OP_OVER
OP_0
OP_NUMNOTEQUAL
OP_3
OP_PICK
OP_0
OP_NUMNOTEQUAL
OP_BOOLAND
OP_IF
OP_SWAP
OP_ROT
OP_3
OP_ROLL
OP_DUP
OP_OVER
call fp_mul
OP_DUP
OP_3
call fp_mul
OP_DUP
OP_OVER
call fp_mul
OP_4
OP_PICK
OP_5
OP_PICK
call fp_mul
OP_DUP
OP_OVER
call fp_mul
OP_DUP
OP_8
call fp_mul
OP_ROT
OP_6
OP_ROLL
call outline_45
OP_3
OP_ROLL
OP_3
OP_ROLL
call fp_mul
OP_2
call fp_mul
OP_ROT
OP_ROT
OP_ROT
OP_3
OP_ROLL
OP_ENDIF
OP_1ADD
OP_ENDIF
OP_FROMALTSTACK
OP_NOT
OP_UNTIL
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_3
OP_ROLL
OP_DROP
OP_ROT
OP_ROT
OP_ROT
end

function outline_25 25
OP_15
OP_ROLL
OP_16
OP_ROLL
push 11
OP_ROLL
call outline_51
end

function outline_10 10
OP_11
OP_ROLL
OP_11
OP_ROLL
OP_11
OP_ROLL
OP_11
OP_ROLL
end

function outline_7 7
OP_6
OP_ROLL
OP_7
OP_ROLL
OP_8
OP_ROLL
OP_9
OP_ROLL
OP_10
OP_ROLL
OP_11
OP_ROLL
end

function outline_13 13
push 17
OP_ROLL
push 17
OP_ROLL
push 17
OP_ROLL
push 17
OP_ROLL
push 17
OP_ROLL
push 17
OP_ROLL
end

function outline_43 43
push d215c38506bda2e452182de584a04fa7f4fdd8eeadaf2ccdd4fef03ab0139700
push e538a124dce66732a3efdb59e5c5b4b5c36ae01b9918be81aeaab8ce409d142b
OP_2SWAP
end

function outline_19 19
push 19
OP_ROLL
push 19
OP_ROLL
push 19
OP_ROLL
push 19
OP_ROLL
end

function outline_44 44
push 17
OP_PICK
push 17
OP_PICK
push 17
OP_PICK
push 17
OP_PICK
push 17
OP_PICK
push 17
OP_PICK
push 11
OP_PICK
push 11
OP_PICK
push 11
OP_PICK
push 11
OP_PICK
push 11
OP_PICK
push 11
OP_PICK
call outline_28
end

function outline_14 14
OP_SWAP
OP_ROT
OP_3
OP_ROLL
OP_4
OP_ROLL
OP_5
OP_ROLL
end

function outline_45 45
call fp_add
OP_DUP
OP_SWAP
call fp_mul
OP_5
OP_ROLL
OP_SWAP
call fp_sub_top_minus_next
OP_ROT
OP_SWAP
call fp_sub_top_minus_next
OP_2
call outline_57
OP_3
OP_ROLL
call fp_mul
OP_ROT
OP_SWAP
call fp_sub_top_minus_next
end

function reduce_mod_p 46
call prime
OP_MOD
end

function prime 0
constant P
end

function outline_15 15
push 11
OP_ROLL
push 11
OP_ROLL
push 11
OP_ROLL
end

function outline_11 11
OP_11
OP_PICK
OP_11
OP_PICK
OP_11
OP_PICK
OP_11
OP_PICK
end

function outline_12 12
OP_13
OP_ROLL
OP_13
OP_ROLL
OP_13
OP_ROLL
OP_13
OP_ROLL
end

function outline_20 20
OP_9
OP_ROLL
OP_10
OP_ROLL
OP_11
OP_ROLL
OP_12
OP_ROLL
OP_13
OP_ROLL
end

function outline_26 26
OP_14
OP_ROLL
OP_15
OP_ROLL
OP_16
OP_ROLL
push 11
OP_ROLL
push 12
OP_ROLL
end

function outline_16 16
OP_ROT
OP_3
OP_ROLL
OP_ROT
OP_3
OP_ROLL
call outline_6
end

function outline_48 48
push 1a
OP_ROLL
push 1b
OP_ROLL
push 1c
OP_ROLL
push 1d
OP_ROLL
push 1e
OP_ROLL
push 1f
OP_ROLL
push 20
OP_ROLL
push 21
OP_ROLL
push 22
OP_ROLL
end

function outline_49 49
call fp_mul
OP_9
OP_ROLL
OP_DROP
OP_9
OP_ROLL
OP_DROP
OP_9
OP_ROLL
OP_DROP
OP_ROT
OP_ROT
OP_ROT
OP_8
OP_ROLL
OP_8
OP_ROLL
OP_8
OP_ROLL
OP_8
OP_ROLL
OP_8
OP_ROLL
OP_8
OP_ROLL
end

function outline_27 27
OP_14
OP_ROLL
OP_DROP
OP_14
OP_ROLL
OP_DROP
OP_14
OP_ROLL
OP_DROP
end

function outline_33 33
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
end

function outline_34 34
call outline_40
call outline_14
call outline_7
OP_12
OP_ROLL
OP_13
OP_ROLL
OP_14
OP_ROLL
call outline_25
call outline_29
end

function outline_21 21
call outline_10
call outline_10
call outline_10
end

function outline_50 50
OP_8
OP_ROLL
OP_9
OP_ROLL
call fp2_mul
OP_6
OP_ROLL
OP_7
OP_ROLL
push 19
OP_PICK
push 19
OP_PICK
call fp2_mul
OP_2
end

function outline_51 51
push 12
OP_ROLL
push 13
OP_ROLL
push 14
OP_ROLL
push 15
OP_ROLL
push 16
OP_ROLL
push 17
OP_ROLL
end

function outline_52 52
push 14
OP_PICK
push 16
OP_PICK
push 18
OP_PICK
end

function outline_53 53
push 15
OP_ROLL
push 15
OP_ROLL
push 15
OP_ROLL
end

function outline_54 54
push 1a
OP_ROLL
push 1a
OP_ROLL
push 1a
OP_ROLL
end

function outline_55 55
OP_6
OP_ROLL
OP_DROP
OP_6
OP_ROLL
OP_DROP
OP_6
OP_ROLL
OP_DROP
end

function outline_56 56
OP_8
OP_ROLL
call outline_20
call outline_26
push 13
OP_ROLL
call outline_24
end

function outline_57 57
call fp_mul
OP_DUP
OP_2
call fp_mul
OP_3
OP_ROLL
call fp_sub_top_minus_next
OP_DUP
OP_ROT
call fp_sub_top_minus_next
end

function outline_58 58
OP_4
OP_ROLL
OP_5
OP_ROLL
OP_6
OP_ROLL
OP_7
OP_ROLL
end

function outline_59 59
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_7
OP_ROLL
end

function outline_60 60
OP_12
OP_ROLL
OP_13
OP_ROLL
OP_14
OP_ROLL
OP_15
OP_ROLL
end

function outline_61 61
OP_11
OP_PICK
OP_11
OP_PICK
call fp2_mul
OP_SWAP
OP_5
OP_PICK
OP_5
OP_PICK
call outline_3
end

function outline_62 62
OP_1
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
OP_0
end

main
# Proof and public-input checks, point arithmetic and Miller accumulation.
OP_OVER
OP_2
OP_PICK
call fp_mul
OP_3
OP_2
OP_PICK
OP_3
OP_PICK
OP_4
OP_PICK
call fp_mul
call fp_mul
call fp_add
OP_NUMEQUALVERIFY
OP_7
OP_PICK
OP_8
OP_PICK
call fp_mul
OP_3
OP_8
OP_PICK
OP_9
OP_PICK
OP_10
OP_PICK
call fp_mul
call fp_mul
call fp_add
OP_NUMEQUALVERIFY
OP_2OVER
call outline_5
OP_5
OP_PICK
OP_5
OP_PICK
OP_2SWAP
OP_SWAP
call fp2_mul
call outline_43
OP_SWAP
call outline_6
OP_7
OP_PICK
OP_7
OP_PICK
call outline_5
OP_SWAP
OP_3
OP_ROLL
OP_NUMEQUALVERIFY
OP_NUMEQUALVERIFY
OP_0
OP_0
OP_1
OP_0
OP_0
OP_0
OP_0
OP_BEGIN
OP_DUP
push 8000
OP_LESSTHAN
OP_DUP
OP_TOALTSTACK
OP_IF
push 7f
OP_OVER
OP_SUB
constant G2_SUBGROUP_SCALAR
OP_SWAP
OP_RSHIFTNUM
OP_2
OP_MOD
OP_1
OP_NUMEQUAL
OP_ROT
OP_3
OP_ROLL
call outline_58
call outline_41
call outline_33
OP_7
OP_ROLL
OP_7
OP_ROLL
OP_IF
OP_12
OP_PICK
OP_12
OP_PICK
OP_12
OP_PICK
OP_12
OP_PICK
OP_5
OP_ROLL
OP_6
OP_ROLL
OP_7
OP_ROLL
OP_8
OP_ROLL
OP_9
OP_ROLL
OP_10
OP_ROLL
OP_6
OP_PICK
OP_8
OP_PICK
OP_10
OP_PICK
OP_12
OP_PICK
OP_1
OP_0
OP_10
OP_PICK
OP_0
OP_NUMNOTEQUAL
OP_12
OP_PICK
OP_0
OP_NUMNOTEQUAL
OP_BOOLOR
OP_IF
OP_11
OP_PICK
OP_11
OP_PICK
call outline_5
OP_2DUP
OP_SWAP
push 11
OP_PICK
push 11
OP_PICK
call fp2_mul
OP_15
OP_PICK
OP_15
OP_PICK
OP_4
OP_PICK
OP_6
OP_PICK
call fp2_mul
OP_2DUP
OP_SWAP
push 17
OP_PICK
push 17
OP_PICK
call fp2_mul
OP_14
OP_PICK
OP_6
OP_PICK
OP_NUMEQUAL
OP_16
OP_PICK
OP_6
OP_PICK
OP_NUMEQUAL
OP_BOOLAND
push 11
OP_PICK
OP_3
OP_PICK
OP_NUMEQUAL
OP_BOOLAND
push 12
OP_PICK
OP_2
OP_PICK
OP_NUMEQUAL
OP_BOOLAND
OP_IF
push 13
OP_PICK
push 13
OP_PICK
push 13
OP_PICK
push 13
OP_PICK
push 13
OP_PICK
push 13
OP_PICK
call outline_41
call outline_27
call outline_27
call outline_33
call outline_12
call outline_12
OP_ELSE
push 11
OP_PICK
push 11
OP_PICK
OP_2
OP_PICK
OP_4
OP_PICK
call outline_3
OP_2
OP_SWAP
OP_ROT
call outline_9
OP_DUP
OP_2
OP_PICK
call outline_5
OP_0
OP_1
push 19
OP_PICK
push 19
OP_PICK
call outline_6
OP_SWAP
call outline_5
OP_12
OP_PICK
OP_14
OP_PICK
OP_ROT
OP_3
OP_ROLL
call outline_3
OP_0
OP_1
OP_ROT
OP_3
OP_ROLL
call outline_3
push 15
OP_PICK
push 15
OP_PICK
OP_12
OP_PICK
OP_14
OP_PICK
call outline_3
OP_DUP
OP_2
call fp_mul
OP_2
OP_PICK
OP_2
call fp_mul
call outline_5
OP_DUP
OP_2
OP_PICK
OP_4
OP_PICK
OP_6
OP_PICK
call fp2_mul
OP_DUP
OP_2
OP_PICK
OP_10
OP_ROLL
OP_11
OP_ROLL
call outline_3
OP_6
OP_ROLL
OP_7
OP_ROLL
call outline_50
OP_OVER
OP_3
OP_PICK
call outline_9
OP_SWAP
OP_6
OP_ROLL
OP_7
OP_ROLL
call outline_3
OP_DUP
OP_2
OP_PICK
OP_4
OP_ROLL
OP_5
OP_ROLL
call outline_3
OP_SWAP
call outline_50
OP_SWAP
OP_ROT
call outline_9
OP_SWAP
OP_ROT
OP_3
OP_ROLL
call outline_3
call outline_27
call outline_27
OP_3
OP_ROLL
OP_3
OP_ROLL
OP_3
OP_ROLL
OP_3
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
call outline_12
call outline_12
OP_ENDIF
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_ENDIF
call outline_55
call outline_55
call outline_55
OP_6
OP_ROLL
OP_DROP
call outline_33
OP_6
OP_ROLL
OP_ENDIF
OP_1ADD
OP_ENDIF
OP_FROMALTSTACK
OP_NOT
OP_UNTIL
OP_DROP
call outline_11
call outline_31
OP_4
OP_PICK
OP_6
OP_PICK
call outline_5
OP_6
OP_ROLL
OP_7
OP_ROLL
OP_2OVER
OP_SWAP
call fp2_mul
OP_2SWAP
OP_SWAP
OP_6
OP_ROLL
OP_7
OP_ROLL
call fp2_mul
OP_2SWAP
OP_SWAP
OP_2ROT
OP_SWAP
call fp2_mul
OP_7
OP_ROLL
OP_4
OP_ROLL
OP_NUMEQUALVERIFY
OP_5
OP_ROLL
OP_3
OP_ROLL
OP_NUMEQUALVERIFY
OP_3
OP_ROLL
OP_ROT
OP_NUMEQUALVERIFY
OP_NUMEQUALVERIFY
OP_SWAP
OP_0
call fp_sub_top_minus_next
OP_SWAP
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
OP_5
OP_ROLL
call outline_40
push 2e0d2d9ef699ec6cf88ebd9752426e7fef31cefaae8a8b7e42eb82816bab1a03
push cbd82919d7d7e412a4d9d9a05b07dfe71097ec2f5a78e718c25c35e119f0b61f
push 8d09a8ae0432eca57880109b41ebfcddd1adb07455e0839aaaabe1d7dc1d092b
push a9320d20c216e73d8abba874c1f6ed64c8e2d879d9ae8786a05f2d87efc53b2d
push 8f4ac3769582d80d7ac41630ceb6e3af666196c11b662ab4a5064f257cab1915
push a073df7a8eba377fb30825337f4741ec0cc699cf20ec3485715f70a79e7d9e26
call outline_34
push 011e54aeff195f51fe6371ee9ca16a24050fc9c5e24925ec48124c7f99a9481b
push 48b8dd157c51e78397383c51b3c72f4a91d984e051e538ef6fe630c0638f7e14
OP_16
OP_ROLL
call outline_42
OP_SWAP
OP_ROT
OP_1
push 912f2ae53356ddff7e3b0bf4bf4a1f034ed3081251396588e04a721a427b5120
push 6036b6f2935ed736ee1829bb711b8c429267b42c46794733ac2700c7af1fc322
call outline_32
push 28372428a8d310ea4b4bd53e7299ec0def2d3d1050906f5cc638999ec6af851e
push 137098eae21a2592ad7d84364f201684007575f2d77b50ee4cc1825a42713e0e
push 13
OP_ROLL
call outline_42
call outline_14
call outline_32
OP_SWAP
OP_ROT
OP_ROT
call prime
OP_DUP
OP_2
OP_SUB
OP_1
OP_3
OP_ROLL
OP_3
OP_PICK
OP_MOD
OP_0
OP_BEGIN
OP_DUP
push fe00
OP_LESSTHAN
OP_DUP
OP_TOALTSTACK
OP_IF
OP_3
OP_PICK
OP_OVER
OP_RSHIFTNUM
OP_2
OP_MOD
OP_1
OP_NUMEQUAL
OP_IF
OP_ROT
OP_2
OP_PICK
OP_MUL
OP_4
OP_PICK
OP_MOD
OP_ROT
OP_ROT
OP_ENDIF
OP_OVER
OP_ROT
OP_MUL
OP_4
OP_PICK
OP_MOD
OP_SWAP
OP_1ADD
OP_ENDIF
OP_FROMALTSTACK
OP_NOT
OP_UNTIL
OP_2DROP
OP_NIP
OP_NIP
OP_DUP
OP_OVER
call fp_mul
OP_SWAP
OP_OVER
call fp_mul
OP_SWAP
OP_ROT
call fp_mul
OP_SWAP
OP_ROT
call fp_mul
OP_SWAP
push a414c853eefa7e2c8531d67232b4bb569a1a50d0ea6daac28a395ccddca2250e
push 49c5269dd8a1f5e6f84a88499aca479527c7cbb88529a44a0b80c6c6758da32f
push be3289dc81093be8a6e4937de1f2d3a7436924b186a11ec8fff173563c4e1c30
push ff38c4abc3a9cd27914c8e50f9ca716cfc0897d21e81df84972fa568f4694a1e
call outline_34
OP_13
OP_ROLL
OP_13
OP_ROLL
push 756f82aeeecd5a031524f79cf6a019a007fb9134682ec4b5d599fdea026d9717
push 7e55d095545fa187dd88844ba3470c4f6357b2ea7449a9563c55d946bfde902f
push 1c9479c1260002be536008ae741c07cd9d3a2879aa45022cbb7c89e34b9bd507
push 58344e5c043f775f489a082a7ff82a9d369a50dd512a9294698c61144acbfc22
call outline_34
call outline_14
call outline_7
call outline_62
OP_12
OP_ROLL
OP_13
OP_ROLL
OP_14
OP_ROLL
call outline_25
# Exact integer derivation of (P^12 - 1) / R from BN_X.
constant BN_X
OP_DUP
OP_DUP
OP_MUL
OP_2DUP
OP_MUL
OP_OVER
OP_2
OP_PICK
OP_MUL
push 24
OP_MUL
push 24
OP_ROT
OP_MUL
OP_ADD
push 18
OP_2
OP_PICK
OP_MUL
OP_ADD
OP_6
OP_3
OP_ROLL
OP_MUL
OP_ADD
OP_1ADD
OP_DUP
OP_6
OP_3
OP_ROLL
OP_MUL
OP_SUB
OP_OVER
OP_ROT
OP_MUL
OP_DUP
OP_MUL
OP_DUP
OP_DUP
OP_MUL
OP_MUL
OP_1SUB
OP_SWAP
OP_DIV
# Full generic final exponentiation and Fp12 identity check.
OP_0
OP_BEGIN
OP_DUP
push e60a
OP_LESSTHAN
OP_DUP
OP_TOALTSTACK
OP_IF
OP_2DUP
OP_RSHIFTNUM
OP_2
OP_MOD
OP_1
OP_NUMEQUAL
OP_IF
OP_2
OP_PICK
OP_4
OP_PICK
OP_6
OP_PICK
OP_8
OP_PICK
OP_10
OP_PICK
OP_12
OP_PICK
OP_14
OP_PICK
OP_16
OP_PICK
push 12
OP_PICK
call outline_52
call outline_48
push 23
OP_ROLL
push 24
OP_ROLL
push 25
OP_ROLL
call outline_29
call outline_21
call outline_19
call outline_19
call outline_19
push 19
OP_ROLL
push 19
OP_ROLL
OP_ENDIF
OP_1ADD
OP_ROT
OP_3
OP_ROLL
OP_4
OP_ROLL
OP_5
OP_ROLL
call outline_7
OP_12
OP_ROLL
OP_13
OP_ROLL
call outline_39
call outline_21
OP_13
OP_ROLL
OP_13
OP_ROLL
OP_ENDIF
OP_FROMALTSTACK
OP_NOT
OP_UNTIL
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_DROP
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_10
OP_ROLL
OP_11
OP_ROLL
OP_1
OP_NUMEQUALVERIFY
OP_10
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_9
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_8
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_7
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_6
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_5
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_4
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_3
OP_ROLL
OP_0
OP_NUMEQUALVERIFY
OP_ROT
OP_0
OP_NUMEQUALVERIFY
OP_SWAP
OP_0
OP_NUMEQUALVERIFY
OP_0
OP_NUMEQUAL
end
