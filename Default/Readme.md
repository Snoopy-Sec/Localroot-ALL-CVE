# Default
This exploit uses the pokemon exploit of the dirtycow vulnerability
as a base and automatically generates a new passwd line.
The user will be prompted for the new password when the binary is run.
The original /etc/passwd file is then backed up to /tmp/passwd.bak
and overwrites the root account with the generated line.
After running the exploit you should be able to login with the newly
created user.