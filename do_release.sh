#! /bin/bash

RELEASE_NOTES=changes/$(changie latest).md

changie merge
goreleaser --release-notes=${RELEASE_NOTES}
