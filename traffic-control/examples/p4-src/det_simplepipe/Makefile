
SRC=det_simplepipe

all:
	# cp ../simple_pipe.p4 ./
	p4c --target bmv2 --std p4-16 -o . ${SRC}.p4
	chmod +x ${SRC}.json

clean:
	rm ${SRC}.json
