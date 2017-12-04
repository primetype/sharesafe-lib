#! /bin/bash

set -e

CMD='stack exec -- sharesafe'

function create_key {
  USER=${1}

  ${CMD} key new -o ${USER}.key
}

function export_public {
  USER=${1}

  ${CMD} key export-public -i ${USER}.key -o ${USER}.pub
}

function create_participant {
  USER=${1}

  echo "Creating participant: ${USER}"

  create_key ${USER}
  export_public ${USER}
}

create_participant "rick"
create_participant "morty"
create_participant "jerry"

${CMD} pvss new -p rick.pub -p morty.pub -p jerry.pub \
  --threshold=2 \
  -c commitments \
  -o encryption-key

${CMD} pvss verify -s rick.share -c commitments
${CMD} pvss verify -s morty.share -c commitments
${CMD} pvss verify -s jerry.share -c commitments

${CMD} pvss open-share -s rick.share -k rick.key -o rick.opened-share
${CMD} pvss open-share -s morty.share -k morty.key -o morty.opened-share

${CMD} pvss recover -s $(cat rick.opened-share) -s $(cat morty.opened-share) \
                    -o encryption-key.recovered

test $(cat encryption-key) = $(cat encryption-key.recovered)

echo "Private message needing 2 participant to open!" | \
  ${CMD} cipher encrypt -k $(cat encryption-key) | \
  ${CMD} cipher decrypt -k $(cat encryption-key.recovered)
