# About This Project

This is just a test project to try different packet-parsing frameworks written in Go.

# Useful packages

* https://pkg.go.dev/github.com/google/gopacket


# Benchmark results

This project `go-pcap-analyzer` is not a full rewrite of the C++-based [https://github.com/f18m/large-pcap-analyzer](large-pcap-analyzer), but still it
makes sense to benchmark the two, asking the `large-pcap-analyzer` to just carry out some basic packet parsing.
Here's the result against a 4.2GB PCAP file:

```
$ make benchmarks

make -s benchmark-lpa
0M packets (492601 packets) were loaded from PCAP.
Parsing stats: 0.00% GTPu with valid inner transport, 0.00% GTPu with valid inner IP, 100.00% with valid transport, 0.00% with valid IP, 0.00% invalid.

real    0m0.848s
user    0m0.211s
sys     0m0.634s


make -s benchmark-go
Done  12  buffer resizing ops; max packet len was 65226 bytes
Successfully opened PCAP file /storage/pcaps/captured_lab_traffic_sample.pcap and read 492601 packets
Closing the PCAP file

real    0m0.898s
user    0m0.273s
sys     0m0.635s
```

This shows that Golang and C++ have basically the same identical processing speed and they are both I/O-bound actually.

