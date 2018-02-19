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

${CMD} pvss verify -s rick.secret-share -c commitments
${CMD} pvss verify -s morty.secret-share -c commitments
${CMD} pvss verify -s jerry.secret-share -c commitments

${CMD} pvss reveal-share -s rick.secret-share -k rick.key -o rick.revealed-share
${CMD} pvss reveal-share -s morty.secret-share -k morty.key -o morty.revealed-share

${CMD} pvss recover -s $(cat rick.revealed-share) -s $(cat morty.revealed-share) \
                    -o encryption-key.recovered

test $(cat encryption-key) = $(cat encryption-key.recovered)

echo "Private message needing 2 participant to open!" | \
  ${CMD} cipher encrypt -k $(cat encryption-key) | \
  ${CMD} cipher decrypt -k $(cat encryption-key.recovered)
