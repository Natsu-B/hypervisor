#!/bin/bash

CRATE_DIRS=("kernel" "boot_loader" "common")

run_cargo_command() {
    local dir_path=$1
    local command=$2

    echo "Running '$command' in $dir_path..."

    output=$(cd "$dir_path" && cargo $command 2>&1)
    local status=$?

    if [ $? -eq 0 ]; then
        echo "Success in $dir_path"
    else
        echo "Error in $dir_path"
    fi
}

clean_projects() {
    for dir in "${CRATE_DIRS[@]}"; do
        run_cargo_command "$dir" "clean"
    done
}

clean_projects
rm -r ./bin/