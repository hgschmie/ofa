#! /bin/bash

RELEASE_NOTES=changes/$(changie latest).md

goreleaser --release-notes=${RELEASE_NOTES}
