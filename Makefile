build: 
	cargo bpf build

run: build
	sudo -E cargo bpf load -i eno1 target/bpf/programs/pfilter/pfilter.elf