#!/bin/bash
set -e
./test_encode    && echo "test_encode: PASS"
./test_transport && echo "test_transport: PASS"
./test_dns_packet && echo "test_dns_packet: PASS"
