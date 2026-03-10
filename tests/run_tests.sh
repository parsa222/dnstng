#!/bin/bash
set -e
./test_encode       && echo "test_encode: PASS"
./test_transport    && echo "test_transport: PASS"
./test_dns_packet   && echo "test_dns_packet: PASS"
./test_channel      && echo "test_channel: PASS"
./test_chain        && echo "test_chain: PASS"
./test_integration  && echo "test_integration: PASS"
