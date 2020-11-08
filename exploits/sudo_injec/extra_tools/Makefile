# relink :)
all:
	# gcc sudo_exec.c -o sudo_exec -static -lutil
	gcc sudo_exec.c -o sudo_exec -pg
	gcc kill_the_sudo.c -o kill_the_sudo -static -lutil
	gcc spawn_process_pid.c -o spawn_process_pid -static
	gcc spawn_process_pid2.c -o spawn_process_pid2 -static
	# gcc read_sudo_token.c -o read_sudo_token -static
	# gcc read_sudo_token_forensic.c -o read_sudo_token_forensic -static
	gcc write_sudo_token.c -o write_sudo_token -static
	gcc parse_process_stat.c -o parse_process_stat -static
	gcc activate_sudo_token.c -o activate_sudo_token -Wno-overflow -static
	gcc take_dev.c -o take_dev -Wno-overflow -static
	gcc fchmod.c -o fchmod -static
	cp activate_sudo_token ../

clean:
	rm -rf spawn_process_pid read_sudo_token write_sudo_token parse_process_stat activate_sudo_token read_sudo_token_forensic sudo_exec kill_the_sudo fchmod
