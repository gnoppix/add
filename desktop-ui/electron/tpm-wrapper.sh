#!/bin/bash
# Wrapper to run add CLI with tss group for TPM access
# This is called by the Electron main process for TPM operations

exec sg tss -c "$(printf '%q ' "$@")"
