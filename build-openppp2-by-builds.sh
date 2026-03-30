#!/bin/bash

# Copyright  : Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved.
# Description: Build openppp2 for multiple configurations using custom CMakeLists.txt files.
# Author: Kyou
# Date: 2026-03-30

# Get script directory (assumed to be /root/dd/openppp2)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR"
CONFIGS_DIR="$BASE_DIR/builds"          # Directory containing custom CMakeLists.txt variants
BIN_DIR="$BASE_DIR/bin"                 # Where final zip files will be placed
BUILD_DIR="$BASE_DIR/build"             # Temporary build directory
ORIGINAL_CMAKELISTS="$BASE_DIR/CMakeLists.txt"
BACKUP_CMAKELISTS="$BASE_DIR/CMakeLists.txt.backup"

# Create bin directory if it doesn't exist
mkdir -p "$BIN_DIR"

# Backup original CMakeLists.txt if not already backed up
if [ -f "$ORIGINAL_CMAKELISTS" ] && [ ! -f "$BACKUP_CMAKELISTS" ]; then
    cp "$ORIGINAL_CMAKELISTS" "$BACKUP_CMAKELISTS"
    echo "Backed up original CMakeLists.txt to $BACKUP_CMAKELISTS"
fi

# Function to restore the original CMakeLists.txt
restore_original() {
    if [ -f "$BACKUP_CMAKELISTS" ]; then
        cp "$BACKUP_CMAKELISTS" "$ORIGINAL_CMAKELISTS"
        echo "Restored original CMakeLists.txt"
    fi
}

# Cleanup on script exit (normal or abnormal)
cleanup() {
    restore_original
    # Remove build directory after all builds
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        echo "Removed build directory: $BUILD_DIR"
    fi
    # Remove backup file to avoid leakage
    if [ -f "$BACKUP_CMAKELISTS" ]; then
        rm -f "$BACKUP_CMAKELISTS"
        echo "Removed backup file: $BACKUP_CMAKELISTS"
    fi
}
trap cleanup EXIT

# Iterate over each configuration file
for config_file in "$CONFIGS_DIR"/*; do
    # Skip if not a regular file
    [ -f "$config_file" ] || continue

    config_name=$(basename "$config_file")
    echo "========================================="
    echo "Building with configuration: $config_name"
    echo "========================================="

    # 1. Backup current CMakeLists.txt (if needed) and replace with config
    if [ -f "$ORIGINAL_CMAKELISTS" ]; then
        cp "$ORIGINAL_CMAKELISTS" "$BACKUP_CMAKELISTS"
    fi
    cp "$config_file" "$ORIGINAL_CMAKELISTS"

    # 2. Prepare build directory
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR" || { echo "Failed to enter build directory"; restore_original; continue; }

    # 3. Configure with CMake
    echo "Running CMake configuration..."
    cmake .. -DCMAKE_BUILD_TYPE=Release
    if [ $? -ne 0 ]; then
        echo "CMake configuration failed for $config_name"
        restore_original
        continue
    fi

    # 4. Build using all available CPU cores
    echo "Building with $(nproc) cores..."
    make -j$(nproc)
    if [ $? -ne 0 ]; then
        echo "Build failed for $config_name"
        restore_original
        continue
    fi

    # 5. Locate the generated ppp executable
    # The binary may be placed in ../bin/ppp (relative to build dir) or directly in build dir
    ppp_executable=""
    # Check in the project bin directory first (where the linker puts it)
    if [ -f "$BASE_DIR/bin/ppp" ]; then
        ppp_executable="$BASE_DIR/bin/ppp"
    else
        # Fallback: search build directory
        ppp_executable=$(find "$BUILD_DIR" -type f -executable -name ppp | head -n 1)
    fi

    if [ -z "$ppp_executable" ] || [ ! -f "$ppp_executable" ]; then
        echo "Could not find ppp executable for $config_name"
        restore_original
        continue
    fi
    echo "Found ppp at: $ppp_executable"

    # 6. Copy executable to bin directory (if not already there)
    if [ "$ppp_executable" != "$BIN_DIR/ppp" ]; then
        cp "$ppp_executable" "$BIN_DIR/ppp"
        if [ ! -f "$BIN_DIR/ppp" ]; then
            echo "Failed to copy ppp to $BIN_DIR/ppp"
            restore_original
            continue
        fi
        echo "Copied ppp to $BIN_DIR/ppp"
    else
        echo "ppp already in bin directory"
    fi

    # 7. Package as zip in bin directory
    zip_filename="${config_name}.zip"
    zip_filepath="$BIN_DIR/$zip_filename"
    rm -f "$zip_filepath"                # Delete old zip if exists
    # Zip the single file (use -j to strip path)
    zip -j "$zip_filepath" "$BIN_DIR/ppp" > /dev/null
    if [ $? -eq 0 ] && [ -f "$zip_filepath" ]; then
        echo "Successfully created $zip_filepath"
    else
        echo "Zip creation failed for $config_name"
    fi

    # 8. Remove ppp from bin directory after packaging (unconditionally)
    rm -f "$BIN_DIR/ppp"
    echo "Removed ppp from bin directory"

    # 9. Restore original CMakeLists.txt for next iteration
    restore_original
done

echo "All builds completed."