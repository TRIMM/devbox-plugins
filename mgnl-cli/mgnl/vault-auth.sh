#!/bin/bash

bao token lookup 2>&1 | grep "permission denied" > /dev/null
if [[ $? -eq 0 ]]; then
    echo "Note: Login to Vault, using SSO."
    bao login -method=oidc
else
    echo "Authenticated to TRIMM Platform Vault"
fi