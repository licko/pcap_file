all:
	gcc -c pcap.c 
	gcc -c pcap_test.c
	gcc -o pcap_test pcap_test.o pcap.o

clean:
	rm -rf pcap_test pcap_test.o pcap.o pcap_test.pcap