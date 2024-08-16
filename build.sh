#!/bin/bash

CRATE_DIRS=("kernel" "mini_loader")

run_cargo_command() {
    local dir_path=$1
    local command=$2
    
    echo "Running '$command' in $dir_path..."
    
    (cd "$dir_path" && cargo $command)
    
    if [ $? -eq 0 ]; then
        echo "Success in $dir_path"
    else
        echo "Error in $dir_path"
    fi
}

build_projects() {
    for dir in "${CRATE_DIRS[@]}"; do
        run_cargo_command "$dir" "build --release"
        check_efi_file "$dir"
    done
}

check_efi_file() {
    local dir_path=$1
    local file="./$dir_path/target/aarch64-unknown-none/release/$dir_path"
    local efi_file="./$dir_path/target/aarch64-unknown-uefi/release/$dir_path.efi"
    
    if [ $dir_path = "mini_loader" ]; then
        if [ -f "$efi_file" ]; then
            echo "$efi_file exists."
            mv $efi_file ./bin/EFI/BOOT/BOOTAA64.EFI
            echo "move it ./bin/EFI/BOOT/BOOTAA64.EFI"
        else
            echo "$efi_file does not exist."
        fi
    else
        if [ -f "$file" ]; then
            echo "$file exists."
            mv $file ./bin/EFI/BOOT/hypervisor
            echo "move it ./bin/EFI/BOOT/hypervisor"
        else
            echo "$file does not exist."
        fi
    fi
}

mkdir -p bin/EFI/BOOT/
build_projects
./run.sh