.data
mac1: .asciiz "enter first number: "
mac2: .asciiz "enter second number: "
result: .asciiz "the answer is: "


.text
.globl main

main:
    li $v0, 4
    la $a0, mac1
    syscall

    li $v0, 5

    syscall
    move $s0, $v0

     li $v0, 4
    la $a0, mac2
    syscall

    li $v0, 5

    syscall
    move $s1, $v0

    add $s2, $s0, $s1
    li $v0, 4
    move $a0, result
    syscall

    li $v0, 1
    move $a0, $s2
    syscall

    li $v0, 10
    syscall

    

