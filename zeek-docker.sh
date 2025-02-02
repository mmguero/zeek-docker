#!/usr/bin/env bash

set -u
set -o pipefail
shopt -s nullglob

ENCODING="utf-8"

function join_by { local IFS="$1"; shift; echo "$*"; }

# Not sure how this would actually work on macOS yet since the container would
# be in a VM, but let's assume somehow it magically would at least for plumbing's sake.
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && BASENAME=gbasename || BASENAME=basename
[[ "$(uname -s)" = 'Darwin' ]] && XARGS=gxargs || XARGS=xargs
if ! (type "$REALPATH" && type "$DIRNAME" && type "$BASENAME" && type "$XARGS") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH, $DIRNAME, $BASENAME and $XARGS"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# If there are any *.zeek files in the same directory as this script,
# we will use them as additional scripts to pass along to zeek in addition
# to the default "local" policy. However, if any of these files begins
# with "local", then the default "local" policy will not be used.
# Similarly, if there is a directory called "intel" in the same
# location as this script it will be also bind mounted and the intelligence
# files inside it will be used by zeek.
pushd $SCRIPT_PATH >/dev/null 2>&1
LOCAL_SCRIPT=local
LOCAL_ZEEK_SCRIPTS=()
for FILE in *.zeek; do
  if [[ -r "$FILE" ]]; then
    LOCAL_ZEEK_SCRIPT="$($BASENAME "$FILE")"
    LOCAL_ZEEK_SCRIPTS+=( "$LOCAL_ZEEK_SCRIPT" )
    [[ "$LOCAL_ZEEK_SCRIPT" =~ ^local ]] && LOCAL_SCRIPT=
  fi
done
[[ -d ./intel ]] && LOCAL_INTEL_DIR="$($REALPATH -e ./intel)" || LOCAL_INTEL_DIR=
[[ -f ./custom/__load__.zeek ]] && LOCAL_CUSTOM_DIR="$($REALPATH -e ./custom)" || LOCAL_CUSTOM_DIR=
popd >/dev/null 2>&1

# pass through local environment variables beginning with ZEEK_
LOCAL_ZEEK_ENV_ARGS=()
while IFS='=' read -r ZEEK_ENV_VAR value ; do
  if [[ $ZEEK_ENV_VAR == 'ZEEK_'* ]]; then
    LOCAL_ZEEK_ENV_ARGS+=( "$ZEEK_ENV_VAR=${!ZEEK_ENV_VAR}" )
  fi
done < <(env)

ZEEK_IMAGE=${ZEEK_IMAGE:-oci.guero.org/zeek:latest}
IMAGE_ARCH_SUFFIX="$(uname -m | sed 's/^x86_64$//' | sed 's/^arm64$/-arm64/' | sed 's/^aarch64$/-arm64/')"
[[ -n "$IMAGE_ARCH_SUFFIX" ]] && [[ "$ZEEK_IMAGE" != *"$IMAGE_ARCH_SUFFIX" ]] && ZEEK_IMAGE="${ZEEK_IMAGE}${IMAGE_ARCH_SUFFIX}"
export ZEEK_IMAGE
export CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
if [[ "$CONTAINER_ENGINE" == "podman" ]]; then
  export DEFAULT_UID=0
  export DEFAULT_GID=0
else
  export DEFAULT_UID=$(id -u)
  export DEFAULT_GID=$(id -g)
fi

export REALPATH
export DIRNAME
export BASENAME
export SCRIPT_PATH
export LOCAL_SCRIPT
export LOCAL_INTEL_DIR
export LOCAL_CUSTOM_DIR
export LOCAL_ZEEK_ARGV="$(join_by ':' "${LOCAL_ZEEK_SCRIPTS[@]}")"
export LOCAL_ZEEK_ENV_ARGV="$(join_by ':' "${LOCAL_ZEEK_ENV_ARGS[@]}")"


# process each argument in parallel with xargs (up to $MAX_ZEEK_PROCS or 4 if unspecified)

printf "%s\0" "$@" | $XARGS -0 -P ${MAX_ZEEK_PROCS:-4} -I XXX bash -c '
  IN_FLAG=
  ZEEK_EXE=
  IN_MOUNT=
  NETWORK_MODE=
  ENV_ARGS=()
  MOUNT_ARGS=()
  CAP_ARGS=()

  if [[ -f "XXX" ]]; then
    # PCAP file
    ZEEK_EXE="zeek"
    MOUNT_ARGS+=( -v )
    MOUNT_ARGS+=( "$($DIRNAME $($REALPATH -e "XXX")):/data:ro" )
    IN_FLAG="-r "/data/$($BASENAME "XXX")""

  elif [[ "$(uname -s)" = "Darwin" ]] && ( networksetup -listallhardwareports | grep -q "^Device: XXX" ); then
    # macOS and this is an interface (ignoring the whole in-a-VM issue)
    IN_FLAG="-i XXX"
    ZEEK_EXE="zeekcap"
    CAP_ARGS=(--cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK)
    NETWORK_MODE="--network host"

  elif [[ -e /sys/class/net/"XXX" ]]; then
    # Linux and this is an interface
    IN_FLAG="-i XXX"
    ZEEK_EXE="zeekcap"
    CAP_ARGS=(--cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK)
    NETWORK_MODE="--network host"

  else
    # what is this?
    echo "Unable to determine type of input argument \"XXX\"" >&2
    exit 1
  fi

  # create a read-only mount for each local zeek script
  IFS=":" read -r -a ZEEK_PARAMS <<< "$LOCAL_ZEEK_ARGV"
  for ZEEK_PARAM in "${ZEEK_PARAMS[@]}"; do
    MOUNT_ARGS+=( -v )
    MOUNT_ARGS+=( "$SCRIPT_PATH/$ZEEK_PARAM:/opt/zeek/share/zeek/site/$ZEEK_PARAM:ro" )
  done

  # pass in external ZEEK_ environment variables
  IFS=":" read -r -a ZEEK_ENVS <<< "$LOCAL_ZEEK_ENV_ARGV"
  for ZEEK_ENV in "${ZEEK_ENVS[@]}"; do
    ENV_ARGS+=( -e )
    ENV_ARGS+=( $ZEEK_ENV )
  done

  # each instance of zeek will write to its own log directory
  LOG_DIR="$(pwd)/$($BASENAME "XXX")"_logs
  mkdir -p "$LOG_DIR"
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$LOG_DIR":/zeek-logs )

  # mount intel directory if specified and exists
  if [[ -d "$LOCAL_INTEL_DIR" ]]; then
    MOUNT_ARGS+=( -v )
    MOUNT_ARGS+=( "$LOCAL_INTEL_DIR":/opt/zeek/share/zeek/site/intel )
    export INTEL_LOAD_FILE=intel_$(echo $RANDOM | md5sum | head -c 20).zeek
    touch "$LOCAL_INTEL_DIR"/"$INTEL_LOAD_FILE"
    ZEEK_PARAMS+=( /opt/zeek/share/zeek/site/intel/$INTEL_LOAD_FILE )
    ENV_ARGS+=( -e )
    ENV_ARGS+=( INTEL_LOAD_FILE )
  else
    INTEL_LOAD_FILE=intel_load_unused
  fi

  # mount CUSTOM directory if specified and exists
  if [[ -d "$LOCAL_CUSTOM_DIR" ]]; then
    MOUNT_ARGS+=( -v )
    MOUNT_ARGS+=( "$LOCAL_CUSTOM_DIR":/opt/zeek/share/zeek/site/custom )
  fi

  # run zeek in a container on the provided input
  $CONTAINER_ENGINE run --rm $NETWORK_MODE \
    -e DEFAULT_UID=$DEFAULT_UID -e DEFAULT_GID=$DEFAULT_GID \
    "${ENV_ARGS[@]}" "${CAP_ARGS[@]}" "${MOUNT_ARGS[@]}" $ZEEK_IMAGE \
    $ZEEK_EXE -C $IN_FLAG $LOCAL_SCRIPT "${ZEEK_PARAMS[@]}"

  # if we generated a temporary load file for intel, delete it
  [[ -f "$LOCAL_INTEL_DIR"/"$INTEL_LOAD_FILE" ]] && rm -f "$LOCAL_INTEL_DIR"/"$INTEL_LOAD_FILE"
'
