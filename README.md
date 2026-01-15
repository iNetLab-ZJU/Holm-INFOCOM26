# Holm-INFOCOM26
# 0、DPU OVS Bridge Configuration
https://docs.nvidia.com/doca/sdk/bluefield+scalable+function+user+guide/index.html

## Create Scalable Function (SF)
```shell
/opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.1 flavour pcisf pfnum 1 sfnum 4
/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.1/294913 hw_addr 00:00:00:00:04:0 trust on state active
echo mlx5_core.sf.4  > /sys/bus/auxiliary/drivers/mlx5_core.sf_cfg/unbind
echo mlx5_core.sf.4  > /sys/bus/auxiliary/drivers/mlx5_core.sf/bind

/opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.1 flavour pcisf pfnum 1 sfnum 5
/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.1/294914 hw_addr 00:00:00:00:05:0 trust on state active
echo mlx5_core.sf.5  > /sys/bus/auxiliary/drivers/mlx5_core.sf_cfg/unbind
echo mlx5_core.sf.5  > /sys/bus/auxiliary/drivers/mlx5_core.sf/bind
```

## SF Bridge Configuration as follows
```shell
c88ec159-93ba-4165-abb6-74a2acac6b9c
    Bridge br2
        Port en3f1pf1sf5
            Interface en3f1pf1sf5
        Port br2
            Interface br2
                type: internal
        Port pf1hpf
            Interface pf1hpf
    Bridge br1
        Port p1
            Interface p1
        Port en3f1pf1sf4
            Interface en3f1pf1sf4
        Port br1
            Interface br1
                type: internal
    ovs_version: "2.10.0-0056-25.01-based-3.3.4"
```

## Configure Hardware Flow Table
```shell
ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
ovs-vsctl get Open_vSwitch . other_config:hw-offload
# Expected return value: "true"
ovs-ofctl add-flow br1 "in_port=p1,actions=output:en3f1pf1sf4"
ovs-ofctl add-flow br2 "in_port=pf1hpf,actions=output:en3f1pf1sf5"
ovs-ofctl add-flow br1 "in_port=en3f1pf1sf4,actions=output:p1"
ovs-ofctl add-flow br2 "in_port=en3f1pf1sf5,actions=output:pf1hpf"
```

# 1、System Architecture
![yuque_mind.jpeg](doc%2Fyuque_mind.jpeg)

1. Priority and port binding mechanism: The highest priority packets are forwarded through the fast path directly to the uplink (host) via hardware forwarding.
2. Decouple packet receiving and transmitting in the thread layer: 4 dedicated threads are used for packet reception and another 4 dedicated threads for packet transmission separately.
3. The memory space for packet reception is divided into 6 independent parts, each abstracted as a ring buffer. The higher the packet priority, the larger the corresponding ring buffer size (which results in fewer packet losses).
4. An independent thread is deployed for rate limiting. Rate limiting operations will be triggered according to specific strategies when congestion is detected on the host side.

# 2、Running Method
```shell
/home/ubuntu/sunxi/simple_fwd_vnf/cmake-build-dpu-soc/simple-fwd-vnf -a auxiliary:mlx5_core.sf.4,dv_flow_en=2 -a auxiliary:mlx5_core.sf.5,dv_flow_en=2 -- -l 60 -o -a
```

# 3、Bandwidth Test

1. Run the program on the ARM side of DPU
```shell
/home/ubuntu/sunxi/simple_fwd_vnf/cmake-build-dpu-soc/simple-fwd-vnf -a auxiliary:mlx5_core.sf.4,dv_flow_en=2 -a auxiliary:mlx5_core.sf.5,dv_flow_en=2 -- -l 60 -o -a
```
2. Run the iperf3 server on the HOST side (5866) of DPU
```shell
iperf3 -s --port 3003
```

3. Run the iperf3 client on the 5558 server
```shell
iperf3 -c 10.0.0.11 --port 3003
```