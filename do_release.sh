#! /bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <release tag>" 1>&2
    exit 1
fi

VERSION=$1 ; shift

changie batch ${VERSION}
RELEASE_NOTES=changes/$(changie latest).md
changie merge

git add $RELEASE_NOTES
git add -u
git commit -m "add changelog for ${VERSION}"

git tag ${VERSION}

goreleaser --release-notes=${RELEASE_NOTES} --rm-dist
