all: build

build:
	rm -rf ./bin
	mkdir ./bin
	javac -d ./bin ./src/edu/wisc/cs/sdn/simpledns/*.java ./src/edu/wisc/cs/sdn/simpledns/packet/*.java

run:
	cd bin && java edu.wisc.cs.sdn.simpledns.SimpleDNS -r a.root-servers.net  -e ../ec2.csv

clean:
	rm -rf ./bin