#! /bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <release tag>" 1>&2
    exit 1
fi

VERSION=$1 ; shift

git tag ${VERSION}
changie batch ${VERSION}

RELEASE_NOTES=changes/$(changie latest).md

changie merge
goreleaser --release-notes=${RELEASE_NOTES}
