dir := $(shell pwd)

all:
	mkdir build
	ln -s $(dir)/dist/nameserver/nameserver build/nameserver
	ln -s $(dir)/dist/proxy/proxy build/proxy

clean:
	rm build -r
