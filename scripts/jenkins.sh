#!/bin/bash

launch_pybluecat () {
  set -ex
  DOCKERIMG='pybluecat'
  DOCKERTAG='master'
  docker pull "$DOCKERIMG":"$DOCKERTAG" && \
  docker run \
    -v ~/.aws:/root/.aws \
    -e AWS_DEFAULT_PROFILE="$AWS_DEFAULT_PROFILE" \
    -e ENVIRONMENT="$ENVIRONMENT" \
    -e REGION="$REGION" \
    -e BLUECAT_USER="$BAM_API_USER" \
    -e BLUECAT_PASS="$BAM_API_PASS" \
    -e BLUECAT_HOST="$BAM_API_HOST" \
    -e BLUECAT_CFG="$BAM_API_CFG" \
    -i --rm "$DOCKERIMG":"$DOCKERTAG" \
    python3 ./scripts/sync-aws-to-bluecat.py --region "$REGION" "$ENV_ARG" --update-bam
}

# The sync script will query all environments by default without an argument
if [[ "$ENVIRONMENT" == "ALL" ]]; then
  ENV_ARG=""
else
  ENV_ARG="--environment ${ENVIRONMENT}"
fi

echo "ENVIRONMENT: ${ENVIRONMENT}"
echo "REGION: ${REGION}"
echo "BLUECAT_HOST: ${BAM_API_HOST}"
echo "BLUECAT_CFG: ${BAM_API_CFG}"
launch_pybluecat
