
# OVN-Kubernetes Traffic Flow Test Scripts (ovn-kuber-traffic-flow-tests)

This repository contains the yaml files and test scripts to test all the traffic flows in an OVN-Kubernetes cluster.

## Table of Contents

- [Different Traffic Flows Tested](#different-traffic-flows-tested)
- [Cluster Deployment](#cluster-deployment)
	- [Upstream OVN-Kubernetes and KIND](#upstream-ovn-kubernetes-and-kind)
	- [OVN-Kubernetes Running on OCP](#ovn-kubernetes-running-on-ocp)
- [Test Pod Deployment](#test-pod-deployment)
  - [Launch Test Pods](#launch-test-pods)
     - [Pin Servers to Given Node](#pin-servers-to-given-node)
     - [Pin Remote Client to Given Node](#pin-remote-client-to-given-node)
     - [Limit Test to Only Host-Backed Pods](#limit-test-to-only-host-backed-pods)
     - [Deploy With SR-IOV VFs](#deploy-with-sr-iov-vfs)
     - [Manage Namespace](#manage-namespace)
     - [Check Variable Settings](#check-variable-settings)
  - [Cleanup Test Pods](#cleanup-test-pods)
  - [Deployment Customization](#deployment-customization)
- [Test Script Usage](#test-script-usage)
  - [curl](#curl)
  - [iperf3](#iperf3)
  - [Hardware Offload Validation](#hardware-offload-validation)
  - [ovnkube-trace](#ovnkube-trace)
- [Container Images](#container-images)
- [Multi-Cluster](#multi-cluster)
  - [mclaunch.sh](#mclaunchsh)
  - [mctest.sh](#mctestsh)
  - [mccleanup.sh](#mccleanupsh)
  - [mcpathtest.sh](#mcpathtestsh)

## Different Traffic Flows Tested

1. Pod to Pod traffic
   * Pod to Pod (Same Node)
   * Pod to Pod (Different Node)
1. Pod to Host traffic
   * Pod to Host (Same Node)
   * Pod to Host (Different Node)
1. Pod -> Cluster IP Service traffic (Pod Backend)
   * Pod to Cluster IP (Pod Backend - Same Node)
   * Pod to Cluster IP (Pod Backend - Different Node)
1. Pod -> Cluster IP Service traffic (Host Backend)
   * Pod to Cluster IP (Host Backend - Same Node)
   * Pod to Cluster IP (Host Backend - Different Node)
1. Pod -> NodePort Service traffic (Pod Backend)
   * Pod -> NodePort Service traffic (Pod Backend - Same Node)
   * Pod -> NodePort Service traffic (Pod Backend - Different Node)
1. Pod -> NodePort Service traffic (Host Backend)
   * Pod -> NodePort Service traffic (Host Backend - Same Node)
   * Pod -> NodePort Service traffic (Host Backend - Different Node)
1. Host to Pod traffic
   * Host to Pod (Same Node)
   * Host to Pod (Different Node)
1. Host to Host traffic
   * Host to Host (Same Node)
   * Host to Host (Different Node)
1. Host -> Cluster IP Service traffic (Pod Backend)
   * Host to Cluster IP (Pod Backend - Same Node)
   * Host to Cluster IP (Pod Backend - Different Node)
1. Host -> Cluster IP Service traffic (Host Backend)
   * Host to Cluster IP (Host Backend - Same Node)
   * Host to Cluster IP (Host Backend - Different Node)
1. Host -> NodePort Service traffic (Pod Backend)
   * Host -> NodePort Service traffic (Pod Backend - Same Node)
   * Host -> NodePort Service traffic (Pod Backend - Different Node)
1. Host -> NodePort Service traffic (Host Backend)
   * Host -> NodePort Service traffic (Host Backend - Same Node)
   * Host -> NodePort Service traffic (Host Backend - Different Node)
1. Cluster -> External Network
   * Pod -> External Network
   * Host -> External Network
1. External Network -> Cluster IP Service traffic
   * External Network -> Cluster IP Service traffic (Pod Backend)
   * External Network -> Cluster IP Service traffic (Host Backend)
   * **NOTE:** External doesn't now about Cluster IP, so these tests are a NOOP.
1. External Network -> NodePort Service traffic
   * External Network -> NodePort Service traffic (Pod Backend)
   * External Network -> NodePort Service traffic (Host Backend)
1. Cluster -> Kubernetes API Server
   * Pod -> Cluster IP Service traffic (Kubernetes API)
   * Host -> Cluster IP Service traffic (Kubernetes API)
1. External Network -> Cluster (multiple external GW traffic)
   * **NOTE:** Special Use-Case for customer - Not Implemented


## Cluster Deployment

### Upstream OVN-Kubernetes and KIND

To test with upstream OVN-Kubernetes and KIND:
```
cd $GOPATH/src/github.com/ovn-org/ovn-kubernetes/contrib/
./kind.sh -ha -wk 4  -gm shared
```

With this KIND Cluster:
* Nodes `ovn-control-plane`, `ovn-worker` and `ovn-worker2` are master nodes.
* Nodes `ovn-worker3`, `ovn-worker4`, `ovn-worker5` and `ovn-worker6` are worker nodes.


### OVN-Kubernetes Running on OCP

Deploy OCP as normal.

In the SR-IOV Lab, the Nodes are as follows:
* Nodes `sriov-master-0`, `sriov-master-1` and `sriov-master-2` are master nodes.
* Nodes `sriov-worker-0` and `sriov-worker-1` are worker nodes.


## Test Pod Deployment

### Launch Test Pods

Test setup is as follows, create POD backed set of resources:
* Run pod-backed *'client'* (DaemonSet) on every node.
* Run one instance of a pod-backed *'http-server'*.
* Create a ClusterIP Service for the pod-backed *'http-server'* using NodePort 8080.
* Create a NodePort Service for the pod-backed *'http-server'* using NodePort 30080.
* Run one instance of a pod-backed *'iperf-server'*.
* Create a ClusterIP Service for the pod-backed *'iperf-server'* using NodePort 5201.
* Create a NodePort Service for the pod-backed *'iperf-server'* using NodePort 30201.

Create Host-POD backed set of resources:
* Run host-backed *'client'* (DaemonSet) on every node.
* Run one instance of a host-backed *'http-server'*.
* Create a ClusterIP Service for the host-backed *'http-server'* using NodePort 8081.
* Create a NodePort Service for the host-backed *'http-server'* using NodePort 30081.
* Run one instance of a host-backed *'iperf-server'*.
* Create a ClusterIP Service for the host-backed *'iperf-server'* using NodePort 5202.
* Create a NodePort Service for the host-backed *'iperf-server'* using NodePort 30202.

The script finds:
* *'client'* pod on the *'Same Node'* as the pod-backed *'server'*
* *'client'* pod on a *'Different Node'* from the pod-backed *'server'*
* *'client'* pod on the *'Same Node'* as the host-pod-backed *'server'*
* *'client'* pod on a *'Different Node'* from the host-pod-backed *'server'*

Once the *'client'* pods (LOCAL and REMOTE, POD and HOST) and IP addresses have been
collected, the script runs *'curl'* commands in different combinations to test each of
traffic flows.


To create all the pods and services (*'client'* DaemonSets, the different *'server'*
instances, and the ClusterIP and NodePort Services):

```
cd ~/src/ovn-kuber-traffic-flow-tests/

./launch.sh
```
It should be noted that `ft-iperf-server-host-v4` gets deleted and remade to bind to the
br-ex interface for UDP tests 4a and 6a. After these 2 UDP tests get run the new
`ft-iperf-server-host-v4` pod gets deleted and the original is applied once more.

#### Pin Servers to Given Node

Each *'server'* (pod backed and host-networked pod backed) needs to be on the same node.
So the setup scripts use labels to achieve this. The default is to schedule the servers
on the first worker node detected. If there is a particular node the *'server'* pods
should run on, for example on an OVS Hardware offloaded node, then use the following
environment variable to force each *'server'* pod on a desired node ('FT_' stands for
Flow Test).  *NOTE:* This needs to be set before the pods are launched.

```
FT_REQ_SERVER_NODE=ovn-worker4 \
./launch.sh

-- OR --

export FT_REQ_SERVER_NODE=ovn-worker4
./launch.sh
```

#### Pin Remote Client to Given Node

Along the same lines, the *'launch.sh'* script creates a *'client'* (pod backed and
host-networked pod backed) on each worker node. The *'test.sh'* script sends packets from
the node on the same node the *'server'* pods are running on (determined as described above)
and a remote node (node *'server'* pods are NOT running on). If there is a particular node
that should be marked as the *' remote client'* node, for example on an OVS Hardware
offloaded node, then use the following environment variable to force the *'test.sh'* script
to pick as the desired node.  *NOTE:* This needs to be set before the *'test.sh'* script is
run and can be changed between each test run.

```
FT_REQ_REMOTE_CLIENT_NODE=ovn-worker3 \
./test.sh

-- OR --

export FT_REQ_REMOTE_CLIENT_NODE=ovn-worker3
./test.sh
```

#### Limit Test to Only Host-Backed Pods

There may be scenarios where only Host-Backed pods need to be tested (i.e. running pods
directly on the DPU). This can be accomplished using the `FT_HOSTONLY` variable. It is
best to export this variable. *'launch.sh'*, *'test.sh'* and *'cleanup.sh'* all need to
be in sync on the value of the `FT_HOSTONLY` variable. *'test.sh'* and *'cleanup.sh'* will
try to detect if it was used on launch, but false positives could occur if pods are renamed
or server pod failed to come up.

```
export FT_HOSTONLY=true"
./launch.sh
./test.sh
./cleanup.sh
```

#### Deploy With SR-IOV VFs

To use Flow-Test with SR-IOV VFs, settings need to be applied before *'launch.sh'*. Flow-Test
needs to know which nodes are running with SR-IOV NICs and needs to know the ResourceName
used by SR-IOV Device Plugin (Flow-Test does not launch or touch SR-IOV Device Plugin).
These settings are controlled with the following variables:

```
export FT_SRIOV_NODE_LABEL=network.operator.openshift.io/external-openvswitch"
export SRIOV_RESOURCE_NAME=openshift.io/mlnx_bf"
./launch.sh
```

The default values (shown above) are the values used by OpenShift in a NVIDIA BlueField-2
deployment. If the default values don't work, apply any label to nodes running with SR-IOV
NICs, and set the variable above. Example:

```
kubectl label nodes ovn-worker4 sriov-node=
kubectl label nodes ovn-worker5 sriov-node=

export FT_SRIOV_NODE_LABEL=sriov-node"
export SRIOV_RESOURCE_NAME=sriov_a"
./launch.sh
```

#### Manage Namespace

By default, all objects (pods, daemonsets, services, etc) are created in the
`default` namespace. This can be overwritten by using the `FT_NAMESPACE` variable.
*'launch.sh'*, *'test.sh'* and *'cleanup.sh'* all need the same value set, so it is best
to export this variable when using.

```
export FT_NAMESPACE=flow-test
./launch.sh
./test.sh
./cleanup.sh
```

#### Check Variable Settings

If you can't remember all the variable names, or to check if they were set in a particular
window, use the `--help` option on each script:

```
./launch.sh --help

This script uses ENV Variables to control test. Here are few key ones:
  FT_HOSTONLY                - Only host network backed pods were launched, off by default.
                               Used on DPUs. It is best to export this variable. test.sh and
                               cleanup.sh will try to detect if it was used on launch, but
                               false positives could occur if pods are renamed or server pod
                               failed to come up. Example:
                                 export FT_HOSTONLY=true
                                 ./launch.sh
                                 ./test.sh
                                 ./cleanup.sh
  FT_REQ_SERVER_NODE         - Node to run server pods on. Must be set before launching
                               pods. Example:
                                 FT_REQ_SERVER_NODE=ovn-worker3 ./launch.sh
  FT_REQ_REMOTE_CLIENT_NODE  - Node to use when sending from client pod on different node
                               from server. Example:
                                 FT_REQ_REMOTE_CLIENT_NODE=ovn-worker4 ./test.sh

Default/Override Values:
  Launch Control:
    FT_HOSTONLY                        false
    FT_REQ_SERVER_NODE                 all
    FT_REQ_REMOTE_CLIENT_NODE          first
  From YAML Files:
    NET_ATTACH_DEF_NAME                ftnetattach
    SRIOV_RESOURCE_NAME                openshift.io/mlnx_bf
    TEST_IMAGE                         quay.io/billy99/ft-base-image:0.7
    HTTP_CLUSTERIP_POD_SVC_PORT        8080
    HTTP_CLUSTERIP_HOST_SVC_PORT       8081
    HTTP_NODEPORT_POD_SVC_PORT         30080
    HTTP_NODEPORT_HOST_SVC_PORT        30081
    IPERF_CLUSTERIP_POD_SVC_PORT       5201
    IPERF_CLUSTERIP_HOST_SVC_PORT      5202
    IPERF_NODEPORT_POD_SVC_PORT        30201
    IPERF_NODEPORT_HOST_SVC_PORT       30202
  Label Management:
    FT_REQ_SERVER_NODE                 all
    FT_SERVER_NODE_LABEL               ft.ServerPod
    FT_CLIENT_NODE_LABEL               ft.ClientPod
```

```
./test.sh --help


This script uses ENV Variables to control test. Here are few key ones:
  TEST_CASE (0 means all)    - Run a single test. Example:
                                 TEST_CASE=3 ./test.sh
  VERBOSE                    - Command output is masked by default. Enable curl output.
                               Example:
                                 VERBOSE=true ./test.sh
  IPERF                      - 'iperf3' can be run on each flow, off by default. Example:
                                 IPERF=true ./test.sh
  HWOL                       - Hardware Offload Validation can be run on each applicable flow.
                               Parameters from IPERF will be used to generate traffic. Example:
                                 HWOL=true ./test.sh
  OVN_TRACE                  - 'ovn-trace' can be run on each flow, off by deafult. Example:
                                 OVN_TRACE=true ./test.sh
  FT_VARS                    - Print script variables. Off by default. Example:
                                 FT_VARS=true ./test.sh
  FT_NOTES                   - Print notes (in blue) where tests are failing but maybe shouldn't be.
                               On by default. Example:
                                 FT_NOTES=false ./test.sh
  CURL_CMD                   - Curl command to run. Allows additional parameters to be
                               inserted. Example:
                                 CURL_CMD="curl -v --connect-timeout 5" ./test.sh
  FT_REQ_REMOTE_CLIENT_NODE  - Node to use when sending from client pod on different node
                               from server. Example:
                                 FT_REQ_REMOTE_CLIENT_NODE=ovn-worker4 ./test.sh
  FT_REQ_SERVER_NODE         - Node to run server pods on. Must be set before launching
                               pods. Example:
                                 FT_REQ_SERVER_NODE=ovn-worker3 ./launch.sh

Default/Override Values:
  Test Control:
    TEST_CASE (0 means all)            0
    VERBOSE                            false
    FT_VARS                            false
    FT_NOTES                           true
:
```

```
./cleanup.sh --help

This script uses ENV Variables to control test. Here are few key ones:
  FT_HOSTONLY                - Only host network backed pods were launched, off by default.
                               Used on DPUs. It is best to export this variable. test.sh and
                               cleanup.sh will try to detect if it was used on launch, but
                               false positives could occur if pods are renamed or server pod
                               failed to come up. Example:
                                 export FT_HOSTONLY=true
                                 ./launch.sh
                                 ./test.sh
                                 ./cleanup.sh
  CLEAN_ALL                  - Remove all generated files (yamls from j2, iperf logs, and
                               ovn-trace logs). Default is to leave in place. Example:
                                 CLEAN_ALL=true ./cleanup.sh

Default/Override Values:
  Launch Control:
    FT_HOSTONLY                        false
    HTTP_SERVER_POD_NAME               ft-http-server-pod-v4
    CLEAN_ALL                          false
    FT_REQ_SERVER_NODE                 all
    FT_REQ_REMOTE_CLIENT_NODE          first
  Label Management:
    FT_REQ_SERVER_NODE                 all
    FT_SERVER_NODE_LABEL               ft.ServerPod
    FT_CLIENT_NODE_LABEL               ft.ClientPod
```

### Cleanup Test Pods

To teardown the test setup:

```
cd ~/src/ovn-kuber-traffic-flow-tests/

./cleanup.sh
```

Several files are generated during test runs. For example, `iperf3` output files,
`ovn-trace` output files, and Pod and Service deployment YAML files (generated
using `j2`). All these are described more below. The files are not deleted by
default. To delete all the generated files, use `CLEAN_ALL`.
To teardown the test setup:

```
cd ~/src/ovn-kuber-traffic-flow-tests/

CLEAN_ALL=true ./cleanup.sh
```

**NOTE:** This is especially important between updates of the repository, because
this is still relatively new and there is still some churn on naming convention of
everything.

### Deployment Customization

This repository uses `j2` to customize the YAML files used to
deploy the Pods and Services. The following fields can be
overridden by setting these variables (with their default values):

```
  SRIOV_RESOURCE_NAME=openshift.io/mlnx_bf
  TEST_IMAGE=quay.io/billy99/ft-base-image:0.7

  HTTP_CLUSTERIP_POD_SVC_PORT=8080
  HTTP_CLUSTERIP_HOST_SVC_PORT=8081
  HTTP_NODEPORT_POD_SVC_PORT=30080
  HTTP_NODEPORT_HOST_SVC_PORT=30081

  IPERF_CLUSTERIP_POD_SVC_PORT=5201
  IPERF_CLUSTERIP_HOST_SVC_PORT=5202
  IPERF_NODEPORT_POD_SVC_PORT=30201
  IPERF_NODEPORT_HOST_SVC_PORT=30202
```

## Test Script Usage

To run all the tests, simply run the script.
* All the hard-coded values are printed to the screen when `FT_VARS=true`.
  The "Test Control", "OVN Trace Control" and "External Access" variables
  can be overwritten. If any of the "From YAML Files" variables are overwritten,
  the yaml files must also be updated before *'launch.sh'* is called.
* Then all the queried values, like Pod Names and IP addresses are printed.
* Each test is run with actual command executed printed to the screen.
* <span style="color:green">**SUCCESS**</span> or <span style="color:red">**FAILED**</span> is then printed.

```
$ FT_VARS=true ./test.sh

Default/Override Values:
  Launch Control:
    FT_HOSTONLY                        false
    FT_CLIENTONLY                      false
    FT_NAMESPACE                       default
    FT_REQ_SERVER_NODE                 all
    FT_REQ_REMOTE_CLIENT_NODE          first
    FT_SRIOV_NODE_LABEL                network.operator.openshift.io/external-openvswitch
    FT_EXPORT_SVC                      false
  Label Management:
    FT_SERVER_NODE_LABEL               ft.ServerPod
    FT_CLIENT_NODE_LABEL               ft.ClientPod
  Test Control:
    TEST_CASE (0 means all)            1
    VERBOSE                            false
    FT_VARS                            true
    FT_NOTES                           true
    FT_DEBUG                           false
    CURL                               true
    CURL_CMD                           curl -m 5
    HWOL                               true
    HWOL_IPERF_TIME                    90
    HWOL_FLOW_LEARNING_TIME            30
    HWOL_TCPDUMP_RUNTIME               30
    HWOL_THRESHOLD_PKT_COUNT           10000
    HWOL_TCP_THRESHOLD_LOW_PKT_RATE    1000000000
    HWOL_UDP_THRESHOLD_LOW_PKT_RATE    500000
    HWOL_SUMMARY_COLUMN_DELIM          ;
    HWOL_INSPECT_SYSTEM_OVS_OVN        false
    IPERF                              false
    IPERF_CMD                          iperf3
    IPERF_TIME                         10
    IPERF_FORWARD_TEST_OPT
    IPERF_REVERSE_TEST_OPT             -R
    FT_CLIENT_CPU_MASK
    OVN_TRACE                          false
    OVN_TRACE_CMD                      ./ovnkube-trace -loglevel=5 -tcp
    FT_SVC_QUALIFIER
    FT_MC_NAMESPACE                    submariner-operator
    FT_MC_CO_SERVER_LABEL              submariner.io/gateway=true
  OVN Trace Control:
    OVN_K_NAMESPACE                    ovn-kubernetes
    SSL_ENABLE                         -noSSL
  From YAML Files:
    NET_ATTACH_DEF_NAME                ftnetattach
    SRIOV_RESOURCE_NAME                openshift.io/mlnx_bf
    TEST_IMAGE                         quay.io/billy99/ft-base-image:0.9
    CLIENT_POD_NAME_PREFIX             ft-client-pod
    http Server:
      HTTP_SERVER_POD_NAME             ft-http-server-pod-v4
      HTTP_SERVER_HOST_POD_NAME        ft-http-server-host-v4
      HTTP_CLUSTERIP_POD_SVC_NAME      ft-http-service-clusterip-pod-v4
      HTTP_CLUSTERIP_POD_SVC_PORT      8080
      HTTP_CLUSTERIP_HOST_SVC_NAME     ft-http-service-clusterip-host-v4
      HTTP_CLUSTERIP_HOST_SVC_PORT     8079
      HTTP_NODEPORT_SVC_NAME           ft-http-service-nodeport-pod-v4
      HTTP_NODEPORT_POD_SVC_PORT       30080
      HTTP_NODEPORT_HOST_SVC_NAME      ft-http-service-nodeport-host-v4
      HTTP_NODEPORT_HOST_SVC_PORT      30079
    iperf Server:
      IPERF_SERVER_POD_NAME            ft-iperf-server-pod-v4
      IPERF_SERVER_HOST_POD_NAME       ft-iperf-server-host-v4
      IPERF_CLUSTERIP_POD_SVC_NAME     ft-iperf-service-clusterip-pod-v4
      IPERF_CLUSTERIP_POD_SVC_PORT     5201
      IPERF_CLUSTERIP_HOST_SVC_NAME    ft-iperf-service-clusterip-host-v4
      IPERF_CLUSTERIP_HOST_SVC_PORT    5202
      IPERF_NODEPORT_POD_SVC_NAME      ft-iperf-service-nodeport-pod-v4
      IPERF_NODEPORT_POD_SVC_PORT      30201
      IPERF_NODEPORT_HOST_SVC_NAME     ft-iperf-service-nodeport-host-v4
      IPERF_NODEPORT_HOST_SVC_PORT     30202
    SERVER_PATH                        /etc/httpserver/
    POD_SERVER_STRING                  Server - Pod Backend Reached
    HOST_SERVER_STRING                 Server - Host Backend Reached
    EXTERNAL_SERVER_STRING             The document has moved
    KUBEAPI_SERVER_STRING              serverAddressByClientCIDRs
  External Access:
    EXTERNAL_IP                        8.8.8.8
    EXTERNAL_URL                       google.com
Queried Values:
  Pod Backed:
    HTTP_SERVER_POD_IP                 10.131.1.66
    IPERF_SERVER_POD_IP                10.131.1.67
    SERVER_POD_NODE                    worker-advnetlab26
    LOCAL_CLIENT_NODE                  worker-advnetlab26
    LOCAL_CLIENT_POD                   ft-client-pod-sriov-x2xd7
    REMOTE_CLIENT_NODE_LIST            worker-advnetlab27
    REMOTE_CLIENT_POD_LIST             ft-client-pod-sriov-p9z2j
    HTTP_CLUSTERIP_POD_SVC_IPV4_LIST   172.30.92.190
    HTTP_CLUSTERIP_POD_SVC_PORT        8080
    HTTP_NODEPORT_POD_SVC_IPV4_LIST    172.30.65.201
    HTTP_NODEPORT_POD_SVC_PORT         30080
    IPERF_CLUSTERIP_POD_SVC_IPV4_LIST  172.30.164.182
    IPERF_CLUSTERIP_POD_SVC_PORT       5201
    IPERF_NODEPORT_POD_SVC_IPV4_LIST   172.30.118.3
    IPERF_NODEPORT_POD_SVC_PORT        30201
  Host backed:
    HTTP_SERVER_HOST_IP                192.168.111.33
    IPERF_SERVER_HOST_IP               192.168.111.33
    SERVER_HOST_NODE                   worker-advnetlab26
    LOCAL_CLIENT_HOST_NODE             worker-advnetlab26
    LOCAL_CLIENT_HOST_POD              ft-client-pod-host-xvhd5
    REMOTE_CLIENT_HOST_NODE_LIST       worker-advnetlab27
    REMOTE_CLIENT_HOST_POD_LIST        ft-client-pod-host-tc9h6
    HTTP_CLUSTERIP_HOST_SVC_IPV4_LIST  172.30.4.237
    HTTP_CLUSTERIP_HOST_SVC_PORT       8079
    HTTP_NODEPORT_HOST_SVC_IPV4_LIST   172.30.232.255
    HTTP_NODEPORT_HOST_SVC_PORT        30079
    IPERF_CLUSTERIP_HOST_SVC_IPV4_LIST 172.30.203.69
    IPERF_CLUSTERIP_HOST_SVC_PORT      5202
    IPERF_NODEPORT_HOST_SVC_IPV4_LIST  172.30.48.14
    IPERF_NODEPORT_HOST_SVC_PORT       30202
  Kubernetes API:
    HTTP_CLUSTERIP_KUBEAPI_SVC_IPV4    172.30.0.1
    HTTP_CLUSTERIP_KUBEAPI_SVC_PORT    443
    HTTP_CLUSTERIP_KUBEAPI_EP_IP       192.168.111.20
    HTTP_CLUSTERIP_KUBEAPI_EP_PORT     6443
    HTTP_CLUSTERIP_KUBEAPI_SVC_NAME    kubernetes.default.svc



FLOW 01: Pod to Pod traffic
---------------------------

*** 1-a: Pod to Pod (Same Node) ***

=== CURL ===
admin:worker-advnetlab26 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-x2xd7 -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    404      0 --:--:-- --:--:-- --:--:--   403

SUCCESS


*** 1-b: Pod to Pod (Different Node) ***

=== CURL ===
admin:worker-advnetlab27 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-p9z2j -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    471      0 --:--:-- --:--:-- --:--:--   472

SUCCESS


FLOW 02: Pod -> Cluster IP Service traffic
------------------------------------------

*** 2-a: Pod to Host (Same Node) ***

=== CURL ===
admin:worker-advnetlab26 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-x2xd7 -- curl -m 5 "http://192.168.111.33:8079/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   170  100   170    0     0    740      0 --:--:-- --:--:-- --:--:--   739

SUCCESS

:
```

Below are some commonly used overrides:

* If a single test needs to be run (this is at the FLOW level):
```
TEST_CASE=3 ./test.sh
```

* For readability, the output of the `curl` is masked. This can be unmasked for debugging:
```
TEST_CASE=3 VERBOSE=true ./test.sh
```

* `iperf3` is disabled by default. To enable and change the timeout (in seconds
and default is 10 seconds):
```
TEST_CASE=3 IPERF=true IPERF_TIME=2 ./test.sh
```

* Hardware Offload Validation is disabled by default. To enable:
```
TEST_CASE=3 HWOL=true ./test.sh
```

* `ovnkube-trace` is disabled by default. To enable:
```
TEST_CASE=3 OVN_TRACE=true ./test.sh
```

* To run on `ovnkube-trace` on OCP:
```
TEST_CASE=3 OVN_TRACE=true SSL_ENABLE=" " OVN_K_NAMESPACE=openshift-ovn-kubernetes ./test.sh
```

* There are a couple of sub-FLOWs that are skipped because they are not
applicable, like External to Service ClusterIP. So there are some test-case
notes (in blue font) for those, for example:
> *** 14-a: External Network -> Cluster IP Service traffic (Pod Backend) ***
>
> curl SvcClusterIP:NODEPORT
> curl -m 5 "http://10.96.238.242:8080/"
> Test Skipped - SVCIP is only in cluster network

To turn off all the test comments:
```
FT_NOTES=false ./test.sh
```

### curl

`curl` is used to test connectivity between pods and ensure a given flow
is working. `curl` is enabled by default, but can be disabled using
`CURL=false`.

```
$ TEST_CASE=1 ./test.sh

FLOW 01: Pod to Pod traffic
---------------------------

*** 1-a: Pod to Pod (Same Node) ***

=== CURL ===
admin:worker-advnetlab26 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-x2xd7 -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    420      0 --:--:-- --:--:-- --:--:--   419

SUCCESS


*** 1-b: Pod to Pod (Different Node) ***

=== CURL ===
admin:worker-advnetlab27 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-p9z2j -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    567      0 --:--:-- --:--:-- --:--:--   569

SUCCESS

```

### iperf3

`iperf3` is used to test packet throughput. It can be used to determine
the rough throughput of each flow. When enabled, `iperf3` is run and a
summary of the results is printed. Both forward and reverse directions
of traffic are tested. Traffic is first sent from client, then traffic
is sent from server (reverse option in `iperf3`).

```
$ TEST_CASE=1 IPERF=true IPERF_TIME=2 ./test.sh

FLOW 01: Pod to Pod traffic
---------------------------

*** 1-a: Pod to Pod (Same Node) ***

=== CURL ===
admin:worker-advnetlab26 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-x2xd7 -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    419      0 --:--:-- --:--:-- --:--:--   420

SUCCESS

=== IPERF ===
== admin:worker-advnetlab26 -> admin:worker-advnetlab26 ==
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3  -c 10.131.1.67 -p 5201 -t 2
Summary (see iperf-logs/01-a-client-server-pod2pod-sameNode.txt for full detail):
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-2.00   sec  5.62 GBytes  24.1 Gbits/sec  947             sender
[  5]   0.00-2.00   sec  5.62 GBytes  24.1 Gbits/sec                  receiver

SUCCESS

== admin:worker-advnetlab26 -> admin:worker-advnetlab26 (Reverse) ==
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3 -R -c 10.131.1.67 -p 5201 -t 2
Summary (see iperf-logs/01-a-server-client-pod2pod-sameNode.txt for full detail):
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-2.00   sec  6.29 GBytes  27.0 Gbits/sec  2187             sender
[  5]   0.00-2.00   sec  6.29 GBytes  27.0 Gbits/sec                  receiver

SUCCESS


*** 1-b: Pod to Pod (Different Node) ***

:
```

When `iperf3` is run on each sub-flow, the full output of the command is piped to
files in the `iperf-logs/` directory. Use `VERBOSE=true` to when command is executed
to see full output command is run. Below is a list of sample output files:

```
$ ls -la
total 204
drwxr-xr-x. 2 root root 4096 Jun 27 17:09 .
drwxr-xr-x. 9 root root 4096 Jun 27 15:36 ..
-rw-r--r--. 1 root root 2833 Jun 27 15:37 01-a-client-server-pod2pod-sameNode.txt
-rw-r--r--. 1 root root 2617 Jun 27 15:38 01-a-server-client-pod2pod-sameNode.txt
-rw-r--r--. 1 root root 2826 Jun 27 15:42 01-b-client-server-pod2pod-diffNode.txt
-rw-r--r--. 1 root root 2616 Jun 27 15:43 01-b-server-client-pod2pod-diffNode.txt
-rw-r--r--. 1 root root 2833 Jun 27 15:47 02-a-client-server-pod2host-sameNode.txt
-rw-r--r--. 1 root root 2626 Jun 27 15:48 02-a-server-client-pod2host-sameNode.txt
-rw-r--r--. 1 root root 2832 Jun 27 15:48 02-b-client-server-pod2host-diffNode.txt
-rw-r--r--. 1 root root 2625 Jun 27 15:49 02-b-server-client-pod2host-diffNode.txt
-rw-r--r--. 1 root root 2837 Jun 27 15:50 03-a-client-server-pod2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2626 Jun 27 15:50 03-a-server-client-pod2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2832 Jun 27 15:55 03-b-client-server-pod2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2625 Jun 27 15:55 03-b-server-client-pod2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2831 Jun 27 16:00 04-a-client-server-pod2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2623 Jun 27 16:00 04-a-server-client-pod2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2829 Jun 27 16:05 04-b-client-server-pod2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2622 Jun 27 16:05 04-b-server-client-pod2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2839 Jun 27 16:10 05-a-client-server-pod2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2628 Jun 27 16:10 05-a-server-client-pod2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2834 Jun 27 16:15 05-b-client-server-pod2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2627 Jun 27 16:16 05-b-server-client-pod2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2835 Jun 27 16:20 06-a-client-server-pod2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2628 Jun 27 16:21 06-a-server-client-pod2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2835 Jun 27 16:25 06-b-client-server-pod2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2627 Jun 27 16:26 06-b-server-client-pod2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2826 Jun 27 16:30 07-a-client-server-host2pod-sameNode.txt
-rw-r--r--. 1 root root 2615 Jun 27 16:31 07-a-server-client-host2pod-sameNode.txt
-rw-r--r--. 1 root root 2824 Jun 27 16:31 07-b-client-server-host2pod-diffNode.txt
-rw-r--r--. 1 root root 2615 Jun 27 16:32 07-b-server-client-host2pod-diffNode.txt
-rw-r--r--. 1 root root 2834 Jun 27 16:32 08-a-client-server-host2host-sameNode.txt
-rw-r--r--. 1 root root 2627 Jun 27 16:33 08-a-server-client-host2host-sameNode.txt
-rw-r--r--. 1 root root 2835 Jun 27 16:33 08-b-client-server-host2host-diffNode.txt
-rw-r--r--. 1 root root 2628 Jun 27 16:34 08-b-server-client-host2host-diffNode.txt
-rw-r--r--. 1 root root 2835 Jun 27 16:34 09-a-client-server-host2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2627 Jun 27 16:35 09-a-server-client-host2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2835 Jun 27 16:40 09-b-client-server-host2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2627 Jun 27 16:40 09-b-server-client-host2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2834 Jun 27 16:45 10-a-client-server-host2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2626 Jun 27 16:45 10-a-server-client-host2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2833 Jun 27 16:50 10-b-client-server-host2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2625 Jun 27 16:50 10-b-server-client-host2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2838 Jun 27 16:55 11-a-client-server-host2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2629 Jun 27 16:55 11-a-server-client-host2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root 2839 Jun 27 17:00 11-b-client-server-host2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2630 Jun 27 17:00 11-b-server-client-host2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root 2776 Jun 27 17:05 12-a-client-server-host2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 2631 Jun 27 17:06 12-a-server-client-host2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root  123 Jun 27 17:09 12-b-client-server-host2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root 2630 Jun 27 17:10 12-b-server-client-host2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root   71 Jun 27 15:36 .gitignore
```

*NOTE:* The *'cleanup.sh'* script does not remove these files and each subsequent run of
*'test.sh'* overwrites the previous test run. They can be removed manually or using
`CLEAN_ALL=true ./cleanup.sh`.

An additional variable is supported when running `iperf3` that allows the executable
to be pinned to a CPU. The CPU Mask is calculated outside of Flow-Test and simply passed
in and set by the script. Example:

```
FT_CLIENT_CPU_MASK=0x100 TEST_CASE=1 IPERF=true CURL=false ./test.sh
```

### Hardware Offload Validation

Hardware Offload Validation is used to determine whether a flow has been hardware
offloaded by examining the RX/TX packet counters from `ethtool` on the
VF representors. When enabled, `iperf3` is run in both forward and reverse traffic
directions, `ethtool` on the VF representor is run at the beginning and end of the
`iperf3` duration, `tcpdump` on the VF representor is run during the `iperf3` duration,
lastly a summary of the results is printed.

```
$ TEST_CASE=1 HWOL=true ./test.sh

FLOW 01: Pod to Pod traffic
---------------------------

*** 1-a: Pod to Pod (Same Node) ***

=== CURL ===
admin:worker-advnetlab26 -> admin:worker-advnetlab26
kubectl exec -n default ft-client-pod-sriov-x2xd7 -- curl -m 5 "http://10.131.1.66:8080/etc/httpserver/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    346      0 --:--:-- --:--:-- --:--:--   346

SUCCESS

=== HWOL ===
== admin:worker-advnetlab26 -> admin:worker-advnetlab26 ==
= Client Pod on Client Host VF Representor Results =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3  -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 8a0d327328be763 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 8a0d327328be763 -n not arp"
Summary (see hwol-logs/01-a-client-server-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 506930587 - 506930587 = 0
TX Packets: 786188362 - 786188362 = 0
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 8a0d327328be763, link-type EN10MB (Ethernet), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel

Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   118 GBytes  25.4 Gbits/sec  18295             sender
[  5]   0.00-40.00  sec   118 GBytes  25.4 Gbits/sec                  receiver

= Client Pod on Server Host VF Representor Results =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3  -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 8a0d327328be763 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 8a0d327328be763 -n not arp"
Summary (see hwol-logs/01-a-client-server-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 506932996 - 506932996 = 0
TX Packets: 786188458 - 786188458 = 0
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 8a0d327328be763, link-type EN10MB (Ethernet), snapshot length 262144 bytes

0 packets captured
0 packets received by filter
0 packets dropped by kernel
Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   119 GBytes  25.6 Gbits/sec  22480             sender
[  5]   0.00-40.00  sec   119 GBytes  25.5 Gbits/sec                  receiver

= Server Pod on Server Host VF Representor Results =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3  -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 3ff7cd6d4ceea68 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 3ff7cd6d4ceea68 -n not arp"
Summary (see hwol-logs/01-a-client-server-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 72890864 - 72890863 = 1
TX Packets: 1188566712 - 1188566711 = 1
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 3ff7cd6d4ceea68, link-type EN10MB (Ethernet), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel

Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   115 GBytes  24.8 Gbits/sec  20058             sender
[  5]   0.00-40.00  sec   115 GBytes  24.8 Gbits/sec                  receiver

SUCCESS

== admin:worker-advnetlab26 -> admin:worker-advnetlab26 (Reverse) ==
= Client Pod on Client Host VF Representor Results (Reverse) =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3 -R -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 8a0d327328be763 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 8a0d327328be763 -n not arp"
Summary (see hwol-logs/01-a-server-client-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 506935220 - 506935220 = 0
TX Packets: 786189775 - 786189775 = 0
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 8a0d327328be763, link-type EN10MB (Ethernet), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel

Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   119 GBytes  25.5 Gbits/sec  20332             sender
[  5]   0.00-40.00  sec   119 GBytes  25.5 Gbits/sec                  receiver

= Client Pod on Server Host VF Representor Results (Reverse) =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3 -R -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 8a0d327328be763 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 8a0d327328be763 -n not arp"
Summary (see hwol-logs/01-a-server-client-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 506935309 - 506935309 = 0
TX Packets: 786192678 - 786192678 = 0
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 8a0d327328be763, link-type EN10MB (Ethernet), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel

Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   118 GBytes  25.3 Gbits/sec  20214             sender
[  5]   0.00-40.00  sec   118 GBytes  25.3 Gbits/sec                  receiver

= Server Pod on Server Host VF Representor Results (Reverse) =
kubectl exec -n default ft-client-pod-sriov-x2xd7 --  iperf3 -R -c 10.131.1.67 -p 5201 -t 40
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "ethtool -S 3ff7cd6d4ceea68 | sed -n 's/^\s\+//p'"
kubectl exec -n "default" "ft-tools-wlmt5" -- /bin/sh -c "timeout --preserve-status 25 tcpdump -v -i 3ff7cd6d4ceea68 -n not arp"
Summary (see hwol-logs/01-a-server-client-pod2pod-sameNode.txt for full detail):
Summary Ethtool results for 8a0d327328be763:
RX Packets: 72898350 - 72898350 = 0
TX Packets: 1188566934 - 1188566934 = 0
Summary Tcpdump Output:
dropped privs to tcpdump
tcpdump: listening on 3ff7cd6d4ceea68, link-type EN10MB (Ethernet), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel

Summary Iperf Output:
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-40.00  sec   118 GBytes  25.3 Gbits/sec  23220             sender
[  5]   0.00-40.00  sec   118 GBytes  25.3 Gbits/sec                  receiver

SUCCESS


*** 1-b: Pod to Pod (Different Node) ***

:
```

When Hardware Offload Validation is run on each sub-flow, the full output of the command
is piped to files in the `hwol-logs/` directory. Use `FT_DEBUG=true` to see all commands
that were used to determine the VF representor and other parameters. Use `VERBOSE=true` to
when command is executed to see full output command is run. Below is a list of sample output
files:

```
$ ls -la
total 9202220
drwxr-xr-x. 2 root root       4096 Jun 27 17:13 .
drwxr-xr-x. 9 root root       4096 Jun 27 15:36 ..
-rw-r--r--. 1 root root      12933 Jun 27 15:40 01-a-client-server-pod2pod-sameNode.txt
-rw-r--r--. 1 root root     498488 Jun 27 15:42 01-a-server-client-pod2pod-sameNode.txt
-rw-r--r--. 1 root root  746031347 Jun 27 15:45 01-b-client-server-pod2pod-diffNode.txt
-rw-r--r--. 1 root root  757263512 Jun 27 15:47 01-b-server-client-pod2pod-diffNode.txt
-rw-r--r--. 1 root root      12829 Jun 27 15:52 03-a-client-server-pod2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root      11993 Jun 27 15:54 03-a-server-client-pod2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root  743947340 Jun 27 15:57 03-b-client-server-pod2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root  763566463 Jun 27 15:59 03-b-server-client-pod2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root  646183167 Jun 27 16:02 04-a-client-server-pod2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 1197152583 Jun 27 16:04 04-a-server-client-pod2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root  143015503 Jun 27 16:07 04-b-client-server-pod2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root  103515987 Jun 27 16:09 04-b-server-client-pod2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root      12869 Jun 27 16:12 05-a-client-server-pod2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root      12027 Jun 27 16:14 05-a-server-client-pod2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root  103712806 Jun 27 16:18 05-b-client-server-pod2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root  102064701 Jun 27 16:20 05-b-server-client-pod2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root  636825401 Jun 27 16:23 06-a-client-server-pod2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root 1136208125 Jun 27 16:25 06-a-server-client-pod2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root   88201000 Jun 27 16:28 06-b-client-server-pod2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root   97731608 Jun 27 16:30 06-b-server-client-pod2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root  512896760 Jun 27 16:37 09-a-client-server-host2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root  214469570 Jun 27 16:39 09-a-server-client-host2clusterIpSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root  434620472 Jun 27 16:42 09-b-client-server-host2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root  198723790 Jun 27 16:44 09-b-server-client-host2clusterIpSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root      12869 Jun 27 16:47 10-a-client-server-host2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root      12035 Jun 27 16:49 10-a-server-client-host2clusterIpSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root      12854 Jun 27 16:52 10-b-client-server-host2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root      12019 Jun 27 16:54 10-b-server-client-host2clusterIpSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root  438399942 Jun 27 16:57 11-a-client-server-host2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root  220658127 Jun 27 16:59 11-a-server-client-host2nodePortSvc-podBackend-sameNode.txt
-rw-r--r--. 1 root root   79049834 Jun 27 17:02 11-b-client-server-host2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root   58111736 Jun 27 17:05 11-b-server-client-host2nodePortSvc-podBackend-diffNode.txt
-rw-r--r--. 1 root root      12883 Jun 27 17:08 12-a-client-server-host2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root       7090 Jun 27 17:09 12-a-server-client-host2nodePortSvc-hostBackend-sameNode.txt
-rw-r--r--. 1 root root       2356 Jun 27 17:11 12-b-client-server-host2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root      12037 Jun 27 17:13 12-b-server-client-host2nodePortSvc-hostBackend-diffNode.txt
-rw-r--r--. 1 root root         70 Jun 27 15:36 .gitignore
```

*NOTE:* The *'cleanup.sh'* script does not remove these files and each subsequent run of
*'test.sh'* overwrites the previous test run. They can be removed manually or using
`CLEAN_ALL=true ./cleanup.sh`.

An additional variable is supported when running Hardware Offload Validation that allows
the `iperf3` executable to be pinned to a CPU. The CPU Mask is calculated outside of Flow-Test
and simply passed in and set by the script. Example:

```
FT_CLIENT_CPU_MASK=0x100 TEST_CASE=1 HWOL=true CURL=false ./test.sh
```

### ovnkube-trace

`ovnkube-trace` is a tool in upstream OVN-Kubernetes to trace packet simulations
between points in ovn-kubernetes. When enabled, `ovnkube-trace` is run on each sub-flow
and the output is piped to files in the `ovn-traces/` directory. Below is a list of
sample output files:

```
$ ls -al ovn-traces/
total 556
drwxrwxr-x. 2 user user  4096 Jun 10 16:46 .
drwxrwxr-x. 7 user user  4096 Jun 11 15:04 ..
-rw-rw-r--. 1 user user 17689 Jun 10 16:51 01-a-pod2pod-sameNode.txt
-rw-rw-r--. 1 user user 18703 Jun 10 16:51 01-b-pod2pod-diffNode.txt
-rw-rw-r--. 1 user user   196 Jun 10 16:51 02-a-pod2host-sameNode.txt
-rw-rw-r--. 1 user user   196 Jun 10 16:51 02-b-pod2host-diffNode.txt
-rw-rw-r--. 1 user user 26265 Jun 10 16:51 03-a-pod2clusterIpSvc-podBackend-sameNode.txt
-rw-rw-r--. 1 user user 27279 Jun 10 16:51 03-b-pod2clusterIpSvc-podBackend-diffNode.txt
-rw-rw-r--. 1 user user 69785 Jun 10 16:51 04-a-pod2clusterIpSvc-hostBackend-sameNode.txt
-rw-rw-r--. 1 user user 28060 Jun 10 16:51 04-b-pod2clusterIpSvc-hostBackend-diffNode.txt
-rw-rw-r--. 1 user user 26240 Jun 10 16:51 05-a-pod2nodePortSvc-podBackend-sameNode.txt
-rw-rw-r--. 1 user user 27254 Jun 10 16:51 05-b-pod2nodePortSvc-podBackend-diffNode.txt
-rw-rw-r--. 1 user user 69772 Jun 10 16:51 06-a-pod2nodePortSvc-hostBackend-sameNode.txt
-rw-rw-r--. 1 user user 28048 Jun 10 16:51 06-b-pod2nodePortSvc-hostBackend-diffNode.txt
-rw-rw-r--. 1 user user  4833 Jun 10 16:51 07-a-host2pod-sameNode.txt
-rw-rw-r--. 1 user user  4833 Jun 10 16:51 07-b-host2pod-diffNode.txt
-rw-rw-r--. 1 user user    72 Jun 10 16:52 08-a-host2host-sameNode.txt
-rw-rw-r--. 1 user user    72 Jun 10 16:52 08-b-host2host-diffNode.txt
-rw-rw-r--. 1 user user 13072 Jun 10 16:52 09-a-host2clusterIpSvc-podBackend-sameNode.txt
-rw-rw-r--. 1 user user 13072 Jun 10 16:52 09-b-host2clusterIpSvc-podBackend-diffNode.txt
-rw-rw-r--. 1 user user  8439 Jun 10 16:52 10-a-host2clusterIpSvc-hostBackend-sameNode.txt
-rw-rw-r--. 1 user user  8439 Jun 10 16:52 10-b-host2clusterIpSvc-hostBackend-diffNode.txt
-rw-rw-r--. 1 user user 13047 Jun 10 16:52 11-a-host2nodePortSvc-podBackend-sameNode.txt
-rw-rw-r--. 1 user user 13047 Jun 10 16:52 11-b-host2nodePortSvc-podBackend-diffNode.txt
-rw-rw-r--. 1 user user  8427 Jun 10 16:52 12-a-host2nodePortSvc-hostBackend-sameNode.txt
-rw-rw-r--. 1 user user  8427 Jun 10 16:52 12-b-host2nodePortSvc-hostBackend-diffNode.txt
-rw-rw-r--. 1 user user 25670 Jun 10 16:52 13-a-pod2external.txt
-rw-rw-r--. 1 user user    72 Jun 10 16:52 13-b-host2external.txt
-rw-rw-r--. 1 user user    19 Jun 10 16:52 14-a-external2clusterIpSvc-podBackend.txt
-rw-rw-r--. 1 user user    19 Jun 10 16:52 14-b-external2clusterIpSvc-hostBackend.txt
-rw-rw-r--. 1 user user    19 Jun 10 16:52 15-a-external2nodePortSvc-podBackend.txt
-rw-rw-r--. 1 user user    19 Jun 10 16:53 15-b-external2nodePortSvc-hostBackend.txt
-rw-rw-r--. 1 user user    70 Apr 16 10:09 .gitignore
```

Examine these files to debug why a particular flow isn't working or to better understand
how a packet flows through OVN-Kubernetes for a particular flow.

*NOTE:* The *'cleanup.sh'* script does not remove these files and each subsequent run of
*'test.sh'* overwrites the previous test run. They can be removed manually or using
`CLEAN_ALL=true ./cleanup.sh`.

## Container Images

See [docs/IMAGES.md](docs/IMAGES.md) for details on the container images used in this repo
and how to rebuild them.


## Multi-Cluster

Test scripts have been setup to run in a Multi-Cluster environment. It has only been tested
with [Submariner](https://github.com/submariner-io) and the clusters themselves need to already
be running. For Multi-Cluster, Flow-Tester is deployed in one of two modes:
* `Full Mode:` Normal deployment of Flow-Tester pods and services and all the Flow-Tester
  Services are exported.
* `Client-Only Mode:` Only Client Pods are created, no Server Pods or Services.

For Multi-Cluster, the following scripts have been added:
* *'mclaunch.sh'* - Loops through all existing clusters and calls *'launch.sh'*.
* *'mctest.sh'* - Loops through all existing clusters and calls *'test.sh'*
* *'mccleanup.sh'* - Loops through all existing clusters and calls *'cleanup.sh'*
* *'mcpathtest.sh'* - Loops through all existing clusters tests that a given client
    can reach the server via each combination of Gateways.

By default, the basic Flow-Tester deployment is launched in the "default" namespace,
but can be overwritten using the `FT_NAMESPACE` environment variable. All the new
Multi-Cluster scripts will use the namespace "flow-test" by default, unless `FT_NAMESPACE`
is specifically set.

### mclaunch.sh

*'mclaunch.sh'* - Loops through all existing clusters and calls *'launch.sh'*, deploying
Flow-Tester in either `Full Mode`, `Client-Only Mode`, or not at all. By default,
Flow-Tester is deployed on all the clusters in `Full Mode` except the last cluster,
which gets deployed in `Client-Only Mode`.
```
   ./mclaunch.sh
```

To control the mode of each cluster, use the following environment variables,
each of which is a list of clusters or the value "all". "all" is the default and
lets the script perform best effort. When an overlap exists, `Full Mode` wins.
```
   export FT_FULL_CLUSTERS="cluster1 cluster3"
   export FT_CO_CLUSTERS="cluster2 cluster4"
   ./mclaunch.sh
```

### mctest.sh

*'mctest.sh'* - Loops through all existing clusters and calls *'test.sh'* if the cluster is
in `Client-Only Mode`. The goal of the test is to test the traffic flow from a pod in
one cluster to a ClusterIP Service in another cluster. Because no Server Pods or
Services are created in `Client-Only Mode`, only ClusterIP Service and External tests
will succeed and are all that are run by this script.
```
   ./mctest.sh
```

When using a remote service, the service must be full qualified (exported services use
`.clusterset.local` whereas local services use `.<ClusterName>.local`). Example:
```
   <ServiceName>.<Namespace>.svc.clusterset.local
```
The *'mctest.sh'* handles this by default, but if the qualifier needs to be changed, or a
fully qualified Service needs to be tested on a single cluster deployment, the following
environment variable can to be used to override:
```
   FT_SVC_QUALIFIER=".flow-test.svc.cluster1.local" ./test.sh
```

To get the DNS domain suffixes for the fully qualified service names, examine the
`/etc/resolv.conf` of a pod in the cluster:
```
   kubectl exec -it -n flow-test ft-client-pod-m9bsr -- cat /etc/resolv.conf
    search flow-test.svc.cluster1.local svc.cluster1.local cluster1.local
    nameserver 100.1.0.10
    options ndots:5
```

In a single cluster environment, `FT_REQ_REMOTE_CLIENT_NODE` is defaulted to `first`.
This implies to choose the first Client Pod that is not on the same node as the Server Pod.
In a multi-cluster environment, `FT_REQ_REMOTE_CLIENT_NODE` is defaulted to `all`, which
causes the script to loop through all of the Client Pods that aren't on the same node as the Server Pod.

### mccleanup.sh

*'mccleanup.sh'* - Loops through all existing clusters and calls *'cleanup.sh'* on each cluster
Flow-Tester is deployed on.
```
   ./mccleanup.sh
```

### mcpathtest.sh

*'mcpathtest.sh'* - Loops through all existing clusters searching for each cluster in `Client-Only Mode`
(no Server Pods running). It then loops through each existing cluster and finds each cluster in `Full Mode`
(with Server Pods running). So every "CO-Cluster" will send packets to every "Full Cluster".

```
--------------------------------------------------------------
                     cluster2 --> cluster1
                     (Client)     (Server)
--------------------------------------------------------------

                          (2)     (5)
                  +--------+       +--------+
                  | Clnt-Y |-------|        |
         (1)  +---|  GW-A  |       |  GW-D  |---+
 +--------+   |   |        |---+ +-|        |   |   +--------+
 |        |---+   +--------+   | | +--------+   +---|        |
 | Clnt-X |                  +-|-+                  | Server |
 |        |---+   +--------+ | |   +--------+   +---|        |
 +--------+   |   |        |-+ +---|        |   |   +--------+
              +---|  GW-B  |       |  GW-C  |---+
                  |        |-------|        |
                  +--------+       +--------+
                          (3)     (4)
```

It then analyses each cluster (CO and Full), finding the nodes the Gateways are on. GW-A and GW-B are on
the CO Cluster. GW-C and GW-D are on the Full Cluster. There will always be a GW-A and GW-D. GWBC and
GW-C may or may not be there depending on the deployment.

It then finds the node the Server is on. If the Server overlaps with a Gateway, it will always be labeled
GW-D.

It then finds a Client Pod that is on a node of one of the Gateways (Clnt-Y). The Gateway with Clnt-Y will
always be labeled GW-A. It then finds a Client Pod that is not on the same node as any of the Gateways
(Clnt-X), if it exists.

It then modifies the multi-hop routes (routes used to load balance between Gateways) by removing one of the
hops, which forces the packets through a given Gateway. The multi-hop routes are labeled (1) - (5).
The script runs a Curl from the Host back Client Pod and Pod back Client Pod for Client-X to the exported
Service. Then repeats for Clnt-Y. It then adjusts the routes and repeats until each of the following
combination of paths are tested:

* PATH 01: A-D -- D-A
* PATH 02: A-D -- D-B
* PATH 03: A-C -- C-A
* PATH 04: A-C -- C-B
* PATH 05: B-D -- D-B
* PATH 06: B-D -- D-A
* PATH 07: B-C -- C-B
* PATH 08: B-C -- C-A

Once all the Paths have been tested, all the routes are restored and the script finds the next set of
clusters to test.

To test all combinations (which is the default), use:

```
   ./mcpathtest.sh
```

There are variables to control how the script runs:

* 'TEST_PATH': Defaults to 0 (which means all). Set to a value 1 to 8 to only test a given path.
* 'FT_CO_CLUSTER': Defaults to "" (which means all). Set to the cluster name if a Client-Only cluster
   to only test a given cluster.
* 'FT_FULL_CLUSTER': Defaults to "" (which means all). Set to the cluster name if a Full cluster
   to only test a given cluster.
* 'FT_DEBUG': Defaults to false. Set to true to debug the script.
* 'PRINT_DBG_CMDS': Defaults to false. Set to true to print additional commands to aid in seeing packets
   flow through the Gateways.

Example:
```

$ PRINT_DBG_CMDS=true FT_FULL_CLUSTER=cluster1 FT_CO_CLUSTER=cluster2 TEST_PATH=4 ./mcpathtest.sh


----------------------
Analyzing Clusters
----------------------

Looping through Cluster List Analyzing ( entries):
 Analyzing Cluster 1: cluster1
  Broker is on cluster1
   Leaving Globalnet flag as false
 Analyzing Cluster 2: cluster2
  Broker not on cluster2
 Analyzing Cluster 3: cluster3
  Broker not on cluster3
 Analyzing Cluster 4: cluster4
  Broker not on cluster4

Looping through Cluster List, Test "Client Only" Clusters:

--------------------------------------------------------------
                     cluster2 --> cluster1
                     (Client)     (Server)
--------------------------------------------------------------

                          (2)     (5)
                  +--------+       +--------+
                  | Clnt-Y |-------|  Server|
         (1)  +---|  GW-A  |       |  GW-D  |
 +--------+   |   |        |---+ +-|        |
 |        |---+   +--------+   | | +--------+
 | Clnt-X |                  +-|-+
 |        |---+   +--------+ | |   +--------+
 +--------+   |   |        |-+ +---|        |
              +---|  GW-B  |       |  GW-C  |
                  |        |-------|        |
                  +--------+       +--------+
                          (3)     (4)

 Clnt-X: cluster2-worker3: ft-client-pod-vxxdd and ft-client-pod-host-wl52h
 Clnt-Y: cluster2-worker2: ft-client-pod-c4f6h and ft-client-pod-host-4hjx5
 GW-A:   cluster2-worker2 172.18.0.9
  docker exec -ti cluster2-worker2 /bin/bash
 GW-B:   cluster2-worker 172.18.0.10
  docker exec -ti cluster2-worker /bin/bash
 GW-C:   cluster1-worker2 172.18.0.18
  docker exec -ti cluster1-worker2 /bin/bash
 GW-D:   cluster1-worker 172.18.0.16
  docker exec -ti cluster1-worker /bin/bash
  apt-get update
  apt-get install -y tcpdump
  ip route list table all > iproutelist.orig
  tcpdump -neep -i any host 100.1.18.136
 Srvr:   SVC-Pod: 100.1.18.136:8080  SVC-Host: 100.1.17.117:8079
 CIDR:   10.2.0.0/16 100.1.0.0/16
 Globalnet=false Server/ClientOverlap=true


PATH 04: A-C -- C-B
-------------------

*** 4-a: Clnt-X to Service Endpoint:Port ***
    Clnt-X -> GW-A -> GW-C -> GW-D -> Svr  U  Svr -> GW-D -> GW-C -> GW-B -> Clnt-X

curl SvcClusterIP:SvcPORT (Pod Backend)
cluster2:cluster2-worker3 -> cluster1:cluster1-worker
kubectl exec -it -n flow-test ft-client-pod-vxxdd -- curl -m 5 "http://100.1.18.136:8080/etc/httpserver/"
SUCCESS

curl SvcClusterIP:SvcPORT (Host Backend)
cluster2:cluster2-worker3 -> cluster1:cluster1-worker
kubectl exec -it -n flow-test ft-client-pod-host-wl52h -- curl -m 5 "http://100.1.17.117:8079/etc/httpserver/"
SUCCESS


*** 4-b: Clnt-Y to Service Endpoint:Port ***
    Clnt-Y/GW-A -> GW-C -> GW-D -> Svr  U  Svr -> GW-D -> GW-C -> GW-B -> GW-A/Clnt-Y

curl SvcClusterIP:SvcPORT (Pod Backend)
cluster2:cluster2-worker2 -> cluster1:cluster1-worker
kubectl exec -it -n flow-test ft-client-pod-c4f6h -- curl -m 5 "http://100.1.18.136:8080/etc/httpserver/"
SUCCESS

curl SvcClusterIP:SvcPORT (Host Backend)
cluster2:cluster2-worker2 -> cluster1:cluster1-worker
kubectl exec -it -n flow-test ft-client-pod-host-4hjx5 -- curl -m 5 "http://100.1.17.117:8079/etc/httpserver/"
SUCCESS


FT_FULL_CLUSTER=cluster1 so skipping over cluster3
FT_CO_CLUSTER=cluster2 so skipping over cluster4

Switched to context "cluster1".
```
