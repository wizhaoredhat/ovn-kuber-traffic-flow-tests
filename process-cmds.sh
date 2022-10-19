#!/bin/bash


#
# Functions
#

process-curl() {
  # The following VARIABLES are used by this function in the following combinations:
  #   From outside Cluster:
  #     TEST_SERVER_HTTP_DST
  #     TEST_SERVER_HTTP_DST_PORT
  #   No Port:
  #     TEST_CLIENT_POD
  #     TEST_SERVER_HTTP_DST
  #   Use Destination and Port:
  #     TEST_CLIENT_POD
  #     TEST_SERVER_HTTP_DST
  #     TEST_SERVER_HTTP_DST_PORT
  #
  #   Debug:
  #     MY_CLUSTER
  #     TEST_CLIENT_NODE
  #     TEST_SERVER_CLUSTER
  #     TEST_SERVER_NODE
  # If not used, VARIABLE should be blank for 'if [ -z "${VARIABLE}" ]' test.

  echo "=== CURL ==="
  echo "${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE}"

  if [ -z "${TEST_CLIENT_POD}" ]; then
    # From External (no 'kubectl exec')
    echo "$CURL_CMD \"http://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}${SERVER_PATH}\""
    TMP_OUTPUT=`$CURL_CMD "http://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}${SERVER_PATH}"`
  elif [ -z "${TEST_SERVER_HTTP_DST_PORT}" ]; then
    # No Port, so leave off Port from command
    echo "kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD \"http://${TEST_SERVER_HTTP_DST}/\""
    TMP_OUTPUT=`kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD "http://${TEST_SERVER_HTTP_DST}/"`
  else
    # Default command

    # If Kubebernetes API, include --cacert and -H TOKEN
    if [ "${TEST_SERVER_RSP}" == "${KUBEAPI_SERVER_STRING}" ]; then
      LCL_SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount

      echo "LCL_TOKEN=kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- cat ${LCL_SERVICEACCOUNT}/token"
      LCL_TOKEN=`kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- cat ${LCL_SERVICEACCOUNT}/token`

      echo "kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD --cacert ${LCL_SERVICEACCOUNT}/ca.crt  -H \"Authorization: Bearer LCL_TOKEN\" -X GET \"https://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}/api\""
      TMP_OUTPUT=`kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD --cacert ${LCL_SERVICEACCOUNT}/ca.crt  -H "Authorization: Bearer ${LCL_TOKEN}" -X GET "https://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}/api"`
    else
      #kubectl config get-contexts
      echo "kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD \"http://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}${SERVER_PATH}\""
      TMP_OUTPUT=`kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- $CURL_CMD "http://${TEST_SERVER_HTTP_DST}:${TEST_SERVER_HTTP_DST_PORT}${SERVER_PATH}"`
    fi
  fi

  # Dump command output
  if [ "$VERBOSE" == true ]; then
    echo "${TMP_OUTPUT}"
  fi

  # Print SUCCESS or FAILURE
  echo "${TMP_OUTPUT}" | grep -cq "${TEST_SERVER_RSP}" && echo -e "\r\n${GREEN}SUCCESS${NC}\r\n" || echo -e "\r\n${RED}FAILED${NC}\r\n"
}

process-iperf() {
  # The following VARIABLES are used by this function:
  #     TEST_CLIENT_POD
  #     FORWARD_TEST_FILENAME
  #     REVERSE_TEST_FILENAME
  #     TEST_SERVER_IPERF_DST
  #     TEST_SERVER_IPERF_DST_PORT
  TASKSET_CMD=""
  if [[ ! -z "${FT_CLIENT_CPU_MASK}" ]]; then
    TASKSET_CMD="taskset ${FT_CLIENT_CPU_MASK} "
  fi

  IPERF_FILENAME_FORWARD_TEST="${IPERF_LOGS_DIR}/${FORWARD_TEST_FILENAME}"
  IPERF_FILENAME_REVERSE_TEST="${IPERF_LOGS_DIR}/${REVERSE_TEST_FILENAME}"

  echo "=== IPERF ==="
  echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} =="
  echo "kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- ${TASKSET_CMD} ${IPERF_CMD} ${IPERF_FORWARD_TEST_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${IPERF_TIME}"
  kubectl exec -n "${FT_NAMESPACE}" "$TEST_CLIENT_POD" -- /bin/sh -c "${TASKSET_CMD} ${IPERF_CMD} ${IPERF_FORWARD_TEST_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${IPERF_TIME}"  > "${IPERF_FILENAME_FORWARD_TEST}"

  # Dump command output
  if [ "$VERBOSE" == true ]; then
    echo "Full Output (from ${IPERF_FILENAME_FORWARD_TEST}):"
    cat ${IPERF_FILENAME_FORWARD_TEST}
  else
    echo "Summary (see ${IPERF_FILENAME_FORWARD_TEST} for full detail):"
    if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
      cat ${IPERF_FILENAME_FORWARD_TEST} | grep -B 1 -A 1 "sender"
    else
      cat ${IPERF_FILENAME_FORWARD_TEST} | grep "0.0\-${IPERF_TIME}"
    fi
  fi

  # Print SUCCESS or FAILURE
  if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
    cat ${IPERF_FILENAME_FORWARD_TEST} | grep -cq "sender" && echo -e "\r\n${GREEN}SUCCESS${NC}\r\n" || echo -e "\r\n${RED}FAILED${NC}\r\n"
  else
    cat ${IPERF_FILENAME_FORWARD_TEST} | grep -cq "0.0\-${IPERF_TIME}" && echo -e "\r\n${GREEN}SUCCESS${NC}\r\n" || echo -e "\r\n${RED}FAILED${NC}\r\n"
  fi

  # Only iperf3 has reverse supported.
  if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
    echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} (Reverse) =="
    echo "kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- ${TASKSET_CMD} ${IPERF_CMD} ${IPERF_REVERSE_TEST_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${IPERF_TIME}"
    kubectl exec -n "${FT_NAMESPACE}" "$TEST_CLIENT_POD" -- /bin/sh -c "${TASKSET_CMD} ${IPERF_CMD} ${IPERF_REVERSE_TEST_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${IPERF_TIME}"  > "${IPERF_FILENAME_REVERSE_TEST}"

    # Dump command output
    if [ "$VERBOSE" == true ]; then
      echo "Full Output (from ${IPERF_FILENAME_REVERSE_TEST}):"
      cat ${IPERF_FILENAME_REVERSE_TEST}
    else
      echo "Summary (see ${IPERF_FILENAME_REVERSE_TEST} for full detail):"
      cat ${IPERF_FILENAME_REVERSE_TEST} | grep -B 1 -A 1 "sender"
    fi

    # Print SUCCESS or FAILURE
    cat ${IPERF_FILENAME_REVERSE_TEST} | grep -cq "sender" && echo -e "\r\n${GREEN}SUCCESS${NC}\r\n" || echo -e "\r\n${RED}FAILED${NC}\r\n"
  fi
}

inspect-system-ovs-ovn() {
  echo "# Gather Debug Info" >> "${HWOL_VALIDATION_FILENAME}"
  echo "## Basic System Information" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: uname -a" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"uname -a\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: rpm -qa | grep openvswitch" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"rpm -qa | grep openvswitch\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ip -d link show" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ip -d link show\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ip addr show" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ip addr show\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ip route" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ip route\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ip neigh" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ip neigh\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ethtool -i ${TEST_VF_REP}" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ethtool -i ${TEST_VF_REP}\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ethtool -i ovn-k8s-mp0" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ethtool -i ovn-k8s-mp0\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: ethtool -i ovn-k8s-mp0_0" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ethtool -i ovn-k8s-mp0_0\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: cat /proc/net/nf_conntrack" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"cat /proc/net/nf_conntrack\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "" >> "${HWOL_VALIDATION_FILENAME}"
  echo "## OvS Information" >> "${HWOL_VALIDATION_FILENAME}"
  # Workaround: https://bugzilla.redhat.com/show_bug.cgi?id=1803920
  OPENVSWITCHPID=`kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"cat /var/run/openvswitch/ovs-vswitchd.pid\""`
  echo "### Command: ovs-vsctl show" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ovs-vsctl show\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: sudo ovs-appctl dpctl/show" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"sudo ovs-appctl -t /var/run/openvswitch/ovs-vswitchd.${OPENVSWITCHPID}.ctl dpctl/show\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: sudo ovs-appctl dpctl/dump-flows --names -m" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"sudo ovs-appctl -t /var/run/openvswitch/ovs-vswitchd.${OPENVSWITCHPID}.ctl dpctl/dump-flows --names -m\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "" >> "${HWOL_VALIDATION_FILENAME}"
  echo "## Kernel TC filter Information" >> "${HWOL_VALIDATION_FILENAME}"
  # Get PF from br-ex
  PF_NAME=`kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ovs-vsctl list-ports br-ex | grep -v patch-br-ex\""`
  echo "NOTE: PF Name is ${PF_NAME}" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ${PF_NAME} ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ${PF_NAME} ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ${PF_NAME} egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ${PF_NAME} egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ${TEST_VF_REP} ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ${TEST_VF_REP} ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ${TEST_VF_REP} egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ${TEST_VF_REP} egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ovn-k8s-mp0_0 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ovn-k8s-mp0_0 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ovn-k8s-mp0_0 egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ovn-k8s-mp0_0 egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ovn-k8s-mp0 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ovn-k8s-mp0 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev ovn-k8s-mp0 egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev ovn-k8s-mp0 egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev genev_sys_6081 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev genev_sys_6081 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev genev_sys_6081 egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev genev_sys_6081 egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev br-int ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev br-int ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev br-int egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev br-int egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev br-ex ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev br-ex ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s filter show dev br-ex egress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s filter show dev br-ex egress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "" >> "${HWOL_VALIDATION_FILENAME}"
  echo "## Kernel TC qdisc Information" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ${PF_NAME} ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ${PF_NAME} ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ${PF_NAME} clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ${PF_NAME} clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ${TEST_VF_REP} ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ${TEST_VF_REP} ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ${TEST_VF_REP} clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ${TEST_VF_REP} clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ovn-k8s-mp0_0 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ovn-k8s-mp0_0 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ovn-k8s-mp0_0 clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ovn-k8s-mp0_0 clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ovn-k8s-mp0 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ovn-k8s-mp0 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev ovn-k8s-mp0 clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev ovn-k8s-mp0 clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev genev_sys_6081 ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev genev_sys_6081 ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev genev_sys_6081 clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev genev_sys_6081 clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev br-int ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev br-int ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev br-int clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev br-int clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev br-ex ingress" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev br-ex ingress\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "### Command: tc -s qdisc show dev br-ex clsact" >> "${HWOL_VALIDATION_FILENAME}"
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"tc -s qdisc show dev br-ex clsact\"" >> "${HWOL_VALIDATION_FILENAME}"
  echo "" >> "${HWOL_VALIDATION_FILENAME}"
  echo "## OVN Information" >> "${HWOL_VALIDATION_FILENAME}"
  echo "Cannot get OVN information." >> "${HWOL_VALIDATION_FILENAME}"
  # rpm -qa | grep ^ovn
  # ovn-nbctl show
  # ovn-sbctl show
  # ovn-nbctl lb-list
  # ovn-nbctl lr-list
  # ovn-nbctl lr-nat-list rtr
  # ovn-nbctl lr-lb-list rtr
  # ovn-nbctl ls-list
  # ovn-nbctl ls-lb-list ls1
  # ovn-nbctl ls-lb-list ls2
}

inspect-vf-rep() {
  # The following VARIABLES are used by this function:
  #     TEST_VF_REP
  #     TEST_TOOLS_POD
  #     RX_COUNT
  retVal=0

  # Record ethtool stats
  [ "$FT_DEBUG" == true ] && echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TEST_TOOLS_POD}\" -- /bin/sh -c \"ethtool -S ${TEST_VF_REP} | sed -n 's/^\s\+//p'\""
  ethtoolstart=$(kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "ethtool -S ${TEST_VF_REP} | sed -n 's/^\s\+//p'")
  echo "${ethtoolstart}" >> "${HWOL_VALIDATION_FILENAME}"

  # Record RX/TX packet counts
  rxpktstart=$(echo "$ethtoolstart" | sed -n "s/^rx_packets:\s\+//p" | sed "s/[^0-9]//g")
  txpktstart=$(echo "$ethtoolstart" | sed -n "s/^tx_packets:\s\+//p" | sed "s/[^0-9]//g")

  # Start tcpdump
  echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TEST_TOOLS_POD}\" -- /bin/sh -c \"timeout --preserve-status ${HWOL_TCPDUMP_RUNTIME} tcpdump -v -i ${TEST_VF_REP} -n not arp\""
  kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "timeout --preserve-status ${HWOL_TCPDUMP_RUNTIME} tcpdump -v -i ${TEST_VF_REP} -n not arp" > "${TCPDUMP_FILENAME}" 2>&1
  tail --lines=2000 "${TCPDUMP_FILENAME}" >> "${HWOL_VALIDATION_FILENAME}"

  # Record ethtool stats
  # This records the ethtool stats before Iperf finishes because at the end of Iperf
  # the TCP connection will close. There are packets when the TCP connection closes
  # that won't be hardware offloaded.
  [ "$FT_DEBUG" == true ] &&  echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TEST_TOOLS_POD}\" -- /bin/sh -c \"ethtool -S ${TEST_VF_REP} | sed -n 's/^\s\+//p'\""
  ethtoolend=$(kubectl exec -n "${FT_NAMESPACE}" "${TEST_TOOLS_POD}" -- /bin/sh -c "ethtool -S ${TEST_VF_REP} | sed -n 's/^\s\+//p'")
  echo "${ethtoolend}" >> "${HWOL_VALIDATION_FILENAME}"

  rxpktend=$(echo "$ethtoolend" | sed -n "s/^rx_packets:\s\+//p" | sed "s/[^0-9]//g")
  txpktend=$(echo "$ethtoolend" | sed -n "s/^tx_packets:\s\+//p" | sed "s/[^0-9]//g")

  rxcount=$(( rxpktend - rxpktstart ))
  txcount=$(( txpktend - txpktstart ))

  if [ "$VERBOSE" == true ]; then
    echo "Tcpdump Output:"
    tail --lines=2000 ${TCPDUMP_FILENAME} | awk NF
  else
    echo "Summary Tcpdump Output:"
    tail ${TCPDUMP_FILENAME} | awk NF
  fi

  echo "Summary Ethtool results for ${TEST_VF_REP}:"
  echo " - RX Packets: ${rxpktend} - ${rxpktstart} = ${rxcount}"
  echo " - TX Packets: ${txpktend} - ${txpktstart} = ${txcount}"

  if (( rxcount > HWOL_THRESHOLD_PKT_COUNT )) || (( txcount > HWOL_THRESHOLD_PKT_COUNT )); then
    if (( rxcount > txcount )); then
      RX_COUNT=${rxcount}
    else
      RX_COUNT=${txcount}
    fi
    retVal=1
  fi

  return $retVal
}

process-vf-rep-stats() {
  # The following VARIABLES are used by this function:
  #     TEST_CLIENT_POD
  #     HWOL_VALIDATION_FILENAME
  #     TEST_SERVER_IPERF_DST
  #     TEST_SERVER_IPERF_DST_PORT
  #     IPERF_OPT
  clientRetVal=0
  clientRxCount=0
  serverRetVal=0
  serverRxCount=0

  IPERF_FILENAME="${HWOL_VALIDATION_FILENAME}.iperf"
  TCPDUMP_FILENAME="${HWOL_VALIDATION_FILENAME}.tcpdump"
  touch "${IPERF_FILENAME}"
  touch "${TCPDUMP_FILENAME}"

  TASKSET_CMD=""
  if [[ ! -z "${FT_CLIENT_CPU_MASK}" ]]; then
    TASKSET_CMD="taskset ${FT_CLIENT_CPU_MASK} "
  fi

  # Start IPERF in background
  KUBE_EXEC_IPERF="kubectl exec -n ${FT_NAMESPACE} ${TEST_CLIENT_POD} -- ${TASKSET_CMD} ${IPERF_CMD} ${IPERF_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${HWOL_IPERF_TIME}"
  kubectl exec -n "${FT_NAMESPACE}" "$TEST_CLIENT_POD" -- /bin/sh -c "${TASKSET_CMD} ${IPERF_CMD} ${IPERF_OPT} -c ${TEST_SERVER_IPERF_DST} -p ${TEST_SERVER_IPERF_DST_PORT} -t ${HWOL_IPERF_TIME}" > "${IPERF_FILENAME}" &
  IPERF_PID=$!

  # Wait to learn flows and hardware offload
  sleep "${HWOL_FLOW_LEARNING_TIME}"

  echo -e "= Client Pod VF Representor Results =" >> "${HWOL_VALIDATION_FILENAME}"
  echo -e "= Client Pod VF Representor Results ="
  kubectl exec -n "${FT_NAMESPACE}" "${CLIENT_TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ethtool -i ${CLIENT_TEST_VF_REP}\"" >> "${HWOL_VALIDATION_FILENAME}"
  if [ $? -eq 0 ]; then
    TEST_VF_REP=${CLIENT_TEST_VF_REP}
    TEST_TOOLS_POD=${CLIENT_TEST_TOOLS_POD}
    RX_COUNT=0
    inspect-vf-rep
    if [ "$HWOL_INSPECT_SYSTEM_OVS_OVN" == true ]; then
      inspect-system-ovs-ovn
    fi
    clientRetVal=$?
    clientRxCount=${RX_COUNT}
  else
    echo -e "The client VF Representor ${CLIENT_TEST_VF_REP} does not exist!" >> "${HWOL_VALIDATION_FILENAME}"
    echo -e "The client VF Representor ${CLIENT_TEST_VF_REP} does not exist!"
  fi

  echo -e "= Server Pod VF Representor Results =" >> "${HWOL_VALIDATION_FILENAME}"
  echo -e "= Server Pod VF Representor Results ="
  kubectl exec -n "${FT_NAMESPACE}" "${SERVER_TEST_TOOLS_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"ethtool -i ${SERVER_TEST_VF_REP}\"" >> "${HWOL_VALIDATION_FILENAME}"
  if [ $? -eq 0 ]; then
    TEST_VF_REP=${SERVER_TEST_VF_REP}
    TEST_TOOLS_POD=${SERVER_TEST_TOOLS_POD}
    RX_COUNT=0
    inspect-vf-rep
    if [ "$HWOL_INSPECT_SYSTEM_OVS_OVN" == true ]; then
      inspect-system-ovs-ovn
    fi
    serverRetVal=$?
    serverRxCount=${RX_COUNT}
  else
    echo -e "The server VF Representor ${SERVER_TEST_VF_REP} does not exist!" >> "${HWOL_VALIDATION_FILENAME}"
    echo -e "The server VF Representor ${SERVER_TEST_VF_REP} does not exist!"
  fi

  # Wait for Iperf to finish
  wait $IPERF_PID

  # Sleep 1 second just in case iperf is still running.
  sleep 1

  # Concatenate the background Iperf results into the same file
  cat "${IPERF_FILENAME}" >> "${HWOL_VALIDATION_FILENAME}"

  # Dump command output
  echo "See ${HWOL_VALIDATION_FILENAME} for full details."
  echo ${KUBE_EXEC_IPERF}
  if [ "$VERBOSE" == true ]; then
    echo "Full Iperf Output:"
    cat ${IPERF_FILENAME}
  else
    echo "Summary Iperf Output:"
    if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
      cat ${IPERF_FILENAME} | grep -B 1 -A 1 "sender"
    else
      cat ${IPERF_FILENAME} | grep "0.0\-${HWOL_IPERF_TIME}"
    fi
  fi

  if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
    cat ${IPERF_FILENAME} | grep -cq "sender" && retVal=0 || retVal=1
  else
    cat ${IPERF_FILENAME} | grep -cq "0.0\-${HWOL_IPERF_TIME}" && retVal=0 || retVal=1
  fi

  if [ ${retVal} -eq 0 ]; then
    if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
      cat ${IPERF_FILENAME} | grep "sender" | awk -v var="$HWOL_SUMMARY_COLUMN_DELIM" '{printf "%s%s%s",var,$7,$8}' >> "${HWOL_SUMMARY_FILENAME}"
    else
      cat ${IPERF_FILENAME} | grep "0.0\-${HWOL_IPERF_TIME}" | awk -v var="$HWOL_SUMMARY_COLUMN_DELIM" '{printf "%s%s%s",var,$7,$8}' >> "${HWOL_SUMMARY_FILENAME}"
    fi
  else
    echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}0 bits/sec" >> "${HWOL_SUMMARY_FILENAME}"
  fi

  DROPCNT=`cat ${IPERF_FILENAME} | grep sec | tr - " " | awk -v thres=${HWOL_THRESHOLD_LOW_PKT_RATE} \
  'BEGIN { cnt = 0 } \
  { if ( $9 == "Gbits/sec" ) value=$8*1000000000; \
    else if ( $9 == "Mbits/sec" ) value=$8*1000000; \
    else if ( $9 == "Kbits/sec" ) value=$8*1000; \
    else value=$8; \
    if ( value < thres ) cnt+=1; } \
  END { print cnt }'`

  echo "There were $DROPCNT drops during Iperf."
  echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}$DROPCNT" >> "${HWOL_SUMMARY_FILENAME}"

  if [ ${clientRetVal} -ne 0 ] || [ ${serverRetVal} -ne 0 ]; then
    echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}Detected ${clientRxCount} Packets On Client and ${serverRxCount} Packets On Server VF Reps" >> "${HWOL_SUMMARY_FILENAME}"
  else
    echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}No Packets Detected On Client Or Server VF Reps" >> "${HWOL_SUMMARY_FILENAME}"
  fi

  if [ ${clientRetVal} -ne 0 ] || [ ${serverRetVal} -ne 0 ] || [ ${retVal} -ne 0 ] || [ ${DROPCNT} -ne 0 ]; then
    retVal=1
  fi

  # Cleanup temporary files
  rm "${IPERF_FILENAME}"
  rm "${TCPDUMP_FILENAME}"

  return $retVal
}

process-hw-offload-validation() {
  # The following VARIABLES are used by this function:
  #     TEST_CLIENT_NODE
  #     TEST_SERVER_NODE
  #     TEST_CLIENT_POD
  #     FORWARD_TEST_FILENAME
  #     REVERSE_TEST_FILENAME
  #     TEST_SERVER_IPERF_DST
  #     TEST_SERVER_IPERF_DST_PORT
  #     IPERF_FORWARD_TEST_OPT
  #     IPERF_REVERSE_TEST_OPT

  [ "$FT_DEBUG" == true ] && echo "kubectl get pods -n ${FT_NAMESPACE} --selector=name=${TOOLS_POD_NAME} -o wide"
  TMP_OUTPUT=$(kubectl get pods -n ${FT_NAMESPACE} --selector=name=${TOOLS_POD_NAME} -o wide)
  TOOLS_CLIENT_POD=$(echo "${TMP_OUTPUT}" | grep -w "${TEST_CLIENT_NODE}" | awk -F' ' '{print $1}')
  TOOLS_SERVER_POD=$(echo "${TMP_OUTPUT}" | grep -w "${TEST_SERVER_NODE}" | awk -F' ' '{print $1}')

  [ "$FT_DEBUG" == true ] && echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TOOLS_SERVER_POD}\" -- /bin/sh -c \"chroot /host /bin/bash -c \"crictl ps -a --name=${IPERF_SERVER_POD_NAME} -o json | jq -r \".containers[].podSandboxId\"\"\""
  TEST_SERVER_IPERF_SERVER_PODID=`kubectl exec -n "${FT_NAMESPACE}" "${TOOLS_SERVER_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"crictl ps -a --name=${IPERF_SERVER_POD_NAME} -o json | jq -r \".containers[].podSandboxId\"\""`
  [ "$FT_DEBUG" == true ] && echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TOOLS_SERVER_POD}\" -- /bin/sh -c \"chroot /host /bin/bash -c \"crictl ps -a --name=${CLIENT_POD_NAME_PREFIX} -o json | jq -r \".containers[].podSandboxId\"\"\""
  TEST_SERVER_CLIENT_PODID=`kubectl exec -n "${FT_NAMESPACE}" "${TOOLS_SERVER_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"crictl ps -a --name=${CLIENT_POD_NAME_PREFIX} -o json | jq -r \".containers[].podSandboxId\"\""`
  [ "$FT_DEBUG" == true ] && echo "kubectl exec -n \"${FT_NAMESPACE}\" \"${TOOLS_CLIENT_POD}\" -- /bin/sh -c \"chroot /host /bin/bash -c \"crictl ps -a --name=${CLIENT_POD_NAME_PREFIX} -o json | jq -r \".containers[].podSandboxId\"\"\""
  TEST_CLIENT_CLIENT_PODID=`kubectl exec -n "${FT_NAMESPACE}" "${TOOLS_CLIENT_POD}" -- /bin/sh -c "chroot /host /bin/bash -c \"crictl ps -a --name=${CLIENT_POD_NAME_PREFIX} -o json | jq -r \".containers[].podSandboxId\"\""`

  TEST_SERVER_IPERF_SERVER_VF_REP=${TEST_SERVER_IPERF_SERVER_PODID::15}
  TEST_SERVER_CLIENT_VF_REP=${TEST_SERVER_CLIENT_PODID::15}
  TEST_CLIENT_CLIENT_VF_REP=${TEST_CLIENT_CLIENT_PODID::15}

  if [ "$FT_DEBUG" == true ]; then
    echo "Variables Used For Hardware Offload Validation:"
    echo "================================================"
    echo "  TOOLS_CLIENT_POD=${TOOLS_CLIENT_POD}"
    echo "  TOOLS_SERVER_POD=${TOOLS_SERVER_POD}"
    echo "  TEST_SERVER_IPERF_SERVER_PODID=${TEST_SERVER_IPERF_SERVER_PODID}"
    echo "  TEST_SERVER_CLIENT_PODID=${TEST_SERVER_CLIENT_PODID}"
    echo "  TEST_CLIENT_CLIENT_PODID=${TEST_CLIENT_CLIENT_PODID}"
    echo "  TEST_SERVER_IPERF_SERVER_VF_REP=${TEST_SERVER_IPERF_SERVER_VF_REP}"
    echo "  TEST_SERVER_CLIENT_VF_REP=${TEST_SERVER_CLIENT_VF_REP}"
    echo "  TEST_CLIENT_CLIENT_VF_REP=${TEST_CLIENT_CLIENT_VF_REP}"
    echo "================================================"
  fi

  echo "=== HWOL ==="
  touch ${HWOL_SUMMARY_FILENAME}

  IPERF_OPT=$IPERF_FORWARD_TEST_OPT
  HWOL_VALIDATION_FILENAME="${HW_OFFLOAD_LOGS_DIR}/${FORWARD_TEST_FILENAME}"
  echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} ==" > "${HWOL_VALIDATION_FILENAME}"
  echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} =="
  echo -ne "${TEST_FILENAME}" >> "${HWOL_SUMMARY_FILENAME}"

  if [ "$CLIENT_SERVER_SAME_NODE" == false ]; then
    CLIENT_TEST_TOOLS_POD=$TOOLS_CLIENT_POD
  else
    CLIENT_TEST_TOOLS_POD=$TOOLS_SERVER_POD
  fi

  if [ "$CLIENT_HOSTBACKED_POD" == false ]; then
    if [ "$CLIENT_SERVER_SAME_NODE" == false ]; then
      CLIENT_TEST_VF_REP=$TEST_CLIENT_CLIENT_VF_REP
    else
      CLIENT_TEST_VF_REP=$TEST_SERVER_CLIENT_VF_REP
    fi
  else
    CLIENT_TEST_VF_REP="ovn-k8s-mp0_0"
  fi

  SERVER_TEST_TOOLS_POD=$TOOLS_SERVER_POD
  if [ "$SERVER_HOSTBACKED_POD" == false ]; then
    SERVER_TEST_VF_REP=$TEST_SERVER_IPERF_SERVER_VF_REP
  else
    SERVER_TEST_VF_REP="ovn-k8s-mp0_0"
  fi

  process-vf-rep-stats
  if [ $? -ne 0 ]; then
    echo -e "\r\n${RED}FAILED${NC}\r\n"
    echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}Fail" >> "${HWOL_SUMMARY_FILENAME}"
  else
    echo -e "\r\n${GREEN}SUCCESS${NC}\r\n"
    echo -ne "${HWOL_SUMMARY_COLUMN_DELIM}Pass" >> "${HWOL_SUMMARY_FILENAME}"
  fi

  # Only iperf3 has reverse supported.
  if [[ "$IPERF_CMD" == *"iperf3"* ]]; then
    IPERF_OPT=$IPERF_REVERSE_TEST_OPT
    HWOL_VALIDATION_FILENAME="${HW_OFFLOAD_LOGS_DIR}/${REVERSE_TEST_FILENAME}"
    echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} (Reverse) ==" > "${HWOL_VALIDATION_FILENAME}"
    echo "== ${MY_CLUSTER}:${TEST_CLIENT_NODE} -> ${TEST_SERVER_CLUSTER}:${TEST_SERVER_NODE} (Reverse) =="

    process-vf-rep-stats
    if [ $? -ne 0 ]; then
      echo -e "\r\n${RED}FAILED${NC}\r\n"
      echo -e "${HWOL_SUMMARY_COLUMN_DELIM}Fail" >> "${HWOL_SUMMARY_FILENAME}"
    else
      echo -e "\r\n${GREEN}SUCCESS${NC}\r\n"
      echo -e "${HWOL_SUMMARY_COLUMN_DELIM}Pass" >> "${HWOL_SUMMARY_FILENAME}"
    fi
  else
    echo -e "" >> "${HWOL_SUMMARY_FILENAME}"
  fi
}

process-ovn-trace() {
  # The following VARIABLES are used by this function in the following combinations:
  #   Use Destination and Port:
  #     TEST_CLIENT_POD
  #     TEST_FILENAME
  #     TEST_SERVER_OVNTRACE_DST
  #     TEST_SERVER_OVNTRACE_DST_PORT
  #   Use Remote Host:
  #     TEST_CLIENT_POD
  #     TEST_FILENAME
  #     TEST_SERVER_OVNTRACE_RMTHOST
  #   Use Service and Port:
  #     TEST_CLIENT_POD
  #     TEST_FILENAME
  #     TEST_SERVER_OVNTRACE_SERVICE
  #     TEST_SERVER_OVNTRACE_DST_PORT
  # If not used, VARIABLE should be blank for 'if [ -z "${VARIABLE}" ]' test.

  echo "OVN-TRACE: BEGIN"
  TRACE_FILENAME="${OVN_TRACE_LOGS_DIR}/${TEST_FILENAME}"

  if [ ! -z "${TEST_SERVER_OVNTRACE_DST}" ]; then
    echo "${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \\"
    echo "  -src=$TEST_CLIENT_POD -dst=$TEST_SERVER_OVNTRACE_DST -dst-port=$TEST_SERVER_OVNTRACE_DST_PORT \\"
    echo "  -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME"

    ${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \
      -src=$TEST_CLIENT_POD -dst=$TEST_SERVER_OVNTRACE_DST -dst-port=$TEST_SERVER_OVNTRACE_DST_PORT \
      -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME
  elif [ ! -z "${TEST_SERVER_OVNTRACE_RMTHOST}" ]; then
    echo ".${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \\"
    echo "  -src=$TEST_CLIENT_POD -remotehost=$TEST_SERVER_OVNTRACE_RMTHOST \\"
    echo "  -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME"

    ${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \
      -src=$TEST_CLIENT_POD -remotehost=$TEST_SERVER_OVNTRACE_RMTHOST \
      -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME
  else
    echo "${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \\"
    echo "  -src=$TEST_CLIENT_POD -service=$TEST_SERVER_OVNTRACE_SERVICE -dst-port=$TEST_SERVER_OVNTRACE_DST_PORT \\"
    echo "  -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME"

    ${OVN_TRACE_CMD} -ovn-config-namespace=$OVN_K_NAMESPACE $SSL_ENABLE \
      -src=$TEST_CLIENT_POD -service=$TEST_SERVER_OVNTRACE_SERVICE -dst-port=$TEST_SERVER_OVNTRACE_DST_PORT \
      -kubeconfig=$KUBECONFIG 2> $TRACE_FILENAME
  fi

  echo "OVN-TRACE: END (see $TRACE_FILENAME for full detail)"
  echo
}
