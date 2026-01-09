## Running holm

Note: Current implementation requires Intel CascadeLake architecture to run correctly. The MSR locations needed for host congestion signals and host-local response with newer architectures will be different. We plan to add support for newer architectures soon (see planned extensions below). 

### Specifying paramters needed to build holm

Specify the required system specific inputs in the *src/config.json* file (for eg., the cores used for collecting host congestion signals, parameters for specifying the granularity of host-local response etc.). More details for each parameter is provided in the README inside the src/ directory. 
```
cd src
vim config.json
```

### Building holm

After modifying the config file, build holm by simply running
```
make
```
This will produce a loadable kernel module (holm-module)

### Running holm

One can run holm by simply loading the kernel module from within the src/ directory
```
sudo insmod holm-module.ko
```
holm can also take any user-specified values for IIO occupancy and PCIe bandwidth thresholds (I_T and B_T used in the [paper](https://www.cs.cornell.edu/~ragarwal/pubs/holm.pdf)) as command line input. More details provided in the README inside the src/ directory. 

To stop running holm simply unload the module
```
sudo rmmod holm-module
```

### Installing required utilities

Instructions to install required set of benchmarking applications and measurement tools (for running similar experiments in SIGCOMM'23 paper) is provided in the README in in *utils/* directory. 
+ Benchmarking applications: We use **iperf3** as network app generating throughput-bound traffic, **netperf** as network app generating latency-sensitive traffic, and **mlc** as the CPU app generating memory-intensive traffic.
+ Measurement tools: We use **Intel PCM** for measuring the host-level metrics and **Intel Memory Bandwidth Allocation** tool for performing host-local response. We also use **sar** utility to measure CPU utilization.

### Specifying desired experimental settings

Desired experiment settings, for eg., enabling DDIO, configuring MTU size, number of clients/servers used by the network-bound app, enabling TCP optimizations like TSO/GRO/aRFS (currently TCP optimizations can be configured using the provided script in this repo only for Mellanox CX5 NICs), etc can tuned using the script *utils/setup-envir.sh*. Run the script with -h flag to get list of all parameters, and their default values.  
```
sudo bash utils/setup-envir.sh -h
```