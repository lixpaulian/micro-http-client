#!/bin/bash
#set -euo pipefail
#IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Bash helper script used in project generate.sh scripts.
# -----------------------------------------------------------------------------

do_add_micro_http_client_xpack() {
  local pack_name='micro-http-client'
  do_tell_xpack "${pack_name}-xpack"

  do_select_pack_folder "lix/${pack_name}.git"

  do_prepare_dest "${pack_name}/src"
  do_add_content "${pack_folder}/src"/*
}

# -----------------------------------------------------------------------------
