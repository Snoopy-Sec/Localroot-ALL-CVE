In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to write before the destination buffer leading to a buffer underflow and potential code execution.

RationalLove.c
glibc < 2.26 - 'getcwd()' Local Privilege Escalation

RationalMetasploit.rb
glibc - 'realpath()' Privilege Escalation (Metasploit)

