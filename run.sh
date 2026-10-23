#!/bin/bash
# Run Difuzzi in Docker on the bundled binary-search example (buggy candidate).
# Usage: export DIFUZZI_LLM_API_KEY and DIFUZZI_LLM_MODEL (a Kimi or Gemini model), then ./run.sh
# Build the image first: docker build --platform linux/amd64 -t difuzzi .
# Report: ./difuzzi-out/report.html


docker run --platform linux/amd64 --rm --user "$(id -u):$(id -g)" -v "$PWD":/work \
    -e DIFUZZI_LLM_API_KEY -e DIFUZZI_LLM_MODEL \
    difuzzi examples/python/binary_search/a.py examples/python/binary_search/b_buggy.py \
    --examples examples/python/binary_search/examples.txt \
    --description examples/python/binary_search/description.txt
