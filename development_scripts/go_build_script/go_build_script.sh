#!/usr/bin/env bash
set -e

APP_NAME="myapp" # Sets the name of the programs file
OUT_DIR="dist" # Sets the directory to be saved to

# Stores the platforms that can be exported to
platforms=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Outputs the app is building
echo "🔨 Building $APP_NAME..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Loops over the platforms in platforms
for platform in "${platforms[@]}"; do
    # Gets the platform information
    IFS=/ read -r GOOS GOARCH <<< "$platform"

    # Creates the output file name
    output="$OUT_DIR/${APP_NAME}-${GOOS}-${GOARCH}"
    # Checks for windows
    if [ "$GOOS" = "windows" ]; then
        # Sets the output to output exe
        output="$output.exe"
    fi

    # Outputs the go architecture
    echo "→ $GOOS/$GOARCH"
    # Compiles the files
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
        go build -trimpath -ldflags="-s -w" -o "$output"
done

# Outputs it is donw
echo "✅ Done. Binaries are in ./$OUT_DIR"
