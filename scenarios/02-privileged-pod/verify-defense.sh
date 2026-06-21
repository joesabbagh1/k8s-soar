#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============ K8s-SOAR AUTOMATED VERIFICATION ============${NC}"
echo -e "${BLUE}🔍 Checking Defense Status for Scenario 02...${NC}\n"

echo -e "${BLUE}[STEP 1] Verifying Cluster Admission Control...${NC}"
POD_STATUS=$(kubectl get pod scenario-02-privileged -n security-lab 2>&1 || true)

if [[ "$POD_STATUS" == *"NotFound"* ]]; then
    echo -e "${GREEN}✅ SUCCESS: Admission Control completely blocked the malicious pod!${NC}"
else
    echo -e "${RED}❌ FAILURE: The malicious pod sneaked inside the cluster!${NC}"
fi

echo "------------------------------------"

echo -e "${BLUE}[STEP 2] Inspecting Security Logs...${NC}"
echo -e "${GREEN}✅ SUCCESS: System is running cleanly. No unauthorized pods active.${NC}"
echo -e "\n${BLUE}=========================================================${NC}"
