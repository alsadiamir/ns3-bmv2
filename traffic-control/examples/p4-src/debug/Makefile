
SRC=debug

all:
	p4c --target bmv2 --arch v1model --std p4-16 -o . ${SRC}.p4
	chmod +x ${SRC}.json

clean:
	rm ${SRC}.json

