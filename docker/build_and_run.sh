#!/usr/bin/env bash

set -e

WORKDIR=$PWD
EHSM_DOCKER_FILE_NAME="ehsm_kms_service.tar.gz"
EHSM_DOCKER_IMAGE_NAME="ehsm_kms_service:latest"
EHSM_DOCKER_IMAGE_NAME_NO_VERSION="ehsm_kms_service"
HOST_PORT=9000
DOCKER_PORT=9000


function build {
	echo "[build] delete the old ehsm docker images and containers..."
	delete

	BUILD_ARGS="--rm --no-cache"
	BUILD_ARGS="$BUILD_ARGS --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy"

	echo "[build] create docker images..."
	docker build $BUILD_ARGS -f $WORKDIR/docker/Dockerfile -t $EHSM_DOCKER_IMAGE_NAME $WORKDIR

	echo "[build] save docker images..."
	docker save $EHSM_DOCKER_IMAGE_NAME | gzip > $WORKDIR/$EHSM_DOCKER_FILE_NAME

	docker rmi $EHSM_DOCKER_IMAGE_NAME 2>/dev/null

    #docker images|grep none|awk '{print $3 }'|xargs docker rmi
}

function run {
	USAGE=$(cat <<- EOM
	Usage: run(-r) <ehsm_kms_service docker images>(optional)

	run the docker image, if you don't add the file name then use the default one($EHSM_DOCKER_FILE_NAME).

	EOM
	)

	echo "$USAGE"
	while [ "$#" -gt 0  ]
	do
	case "$1" in
		-h|--help)
		echo "$USAGE"
		exit
		;;

		*)
		EHSM_DOCKER_FILE_NAME=($1)
        shift
        ;;
	esac
	done

	docker load -i $EHSM_DOCKER_FILE_NAME

	RUN_ARG="--env http_proxy=$http_proxy --env https_proxy=$https_proxy"
	RUN_ARG="$RUN_ARG --device=/dev/sgx/enclave -v aesmd-socket:/var/run/aesmd"

	# run the container
	docker run -d $RUN_ARG -it -p $HOST_PORT:$DOCKER_PORT $EHSM_DOCKER_IMAGE_NAME
}

function delete {
	container_id=$(docker ps | grep -E $EHSM_DOCKER_IMAGE_NAME |awk '{print $1}')
	if [ ! -z "$container_id" ]; then
		echo "rm containers..."
		docker rm -f $container_id
	fi

	img_id=$(docker images | grep -E $EHSM_DOCKER_IMAGE_NAME_NO_VERSION |awk '{print $3}')
	if [ ! -z "$img_id" ]; then
		echo "rm docker image..."
		docker rmi -f $img_id
	fi
}


USAGE=$(cat <<- EOM
Usage: build_and_run.sh <Commands>
Commands:
  -b | build    Build the docker image for the ehsm_kms_service.
  -r | run      Run the docker image.
  -d | delete   Delete the container and the docker image.

EOM
)

subcmd="$1"
case $subcmd in
	build | -b)
		shift
		build $@
		;;

	run | -r)
		shift
		run $@
		;;

	delete | -d)
		shift
		delete $@
		;;

	*)
		echo "$USAGE"
		exit
		;;
esac


exit

