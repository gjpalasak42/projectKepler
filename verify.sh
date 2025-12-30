#!/bin/bash

# ProjectKepler Verification Script
# Validates build health and diagnostics status

set -e

echo "================================================"
echo "ProjectKepler Build Verification"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "build.gradle" ]; then
    echo -e "${RED}❌ Error: build.gradle not found. Run this script from the project root.${NC}"
    exit 1
fi

echo "📋 Step 1: Verifying project structure..."
if [ -d "src/main/java/com/projectkepler/burp" ]; then
    echo -e "${GREEN}✅ Source directory: src/main/java/com/projectkepler/burp${NC}"
else
    echo -e "${RED}❌ Source directory not found${NC}"
    exit 1
fi

# Count Kotlin files
KOTLIN_FILES=$(find src/main/java/com/projectkepler/burp -name "*.kt" | wc -l | tr -d ' ')
echo -e "${GREEN}✅ Found $KOTLIN_FILES Kotlin source files${NC}"
echo ""

echo "🧹 Step 2: Cleaning build artifacts..."
./gradlew clean > /dev/null 2>&1
echo -e "${GREEN}✅ Clean complete${NC}"
echo ""

echo "🔨 Step 3: Compiling Kotlin sources..."
if ./gradlew compileKotlin --console=plain 2>&1 | grep -q "BUILD SUCCESSFUL"; then
    echo -e "${GREEN}✅ Compilation successful (0 errors)${NC}"
else
    echo -e "${RED}❌ Compilation failed${NC}"
    ./gradlew compileKotlin
    exit 1
fi
echo ""

echo "📦 Step 4: Building Fat JAR..."
if ./gradlew shadowJar --console=plain 2>&1 | grep -q "BUILD SUCCESSFUL"; then
    echo -e "${GREEN}✅ Shadow JAR built successfully${NC}"
else
    echo -e "${RED}❌ Shadow JAR build failed${NC}"
    exit 1
fi

# Check JAR exists
if [ -f "build/libs/projectKepler-1.2.1.jar" ]; then
    JAR_SIZE=$(ls -lh build/libs/projectKepler-1.2.1.jar | awk '{print $5}')
    echo -e "${GREEN}✅ JAR artifact: build/libs/projectKepler-1.2.1.jar ($JAR_SIZE)${NC}"
else
    echo -e "${RED}❌ JAR artifact not found${NC}"
    exit 1
fi
echo ""

echo "🔐 Step 5: Generating SHA-256 checksum..."
cd build/libs
SHA256=$(shasum -a 256 projectKepler-1.2.1.jar | awk '{print $1}')
echo "$SHA256" > projectKepler-1.2.1.jar.sha256
echo -e "${GREEN}✅ Checksum: $SHA256${NC}"
cd - > /dev/null
echo ""

echo "🔍 Step 6: Checking for phantom files..."
if find src/main/java/burp -name "*.kt" 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}⚠️  Warning: Old 'burp' package files still exist${NC}"
    echo "   These should have been deleted during refactoring."
else
    echo -e "${GREEN}✅ No phantom files found${NC}"
fi
echo ""

echo "📊 Step 7: Project metrics..."
echo "   Total Kotlin files: $KOTLIN_FILES"
echo "   Package: com.projectkepler.burp"
echo "   Kotlin version: 1.9.24"
echo "   Java toolchain: 17"
echo "   Montoya API: 2023.12.1"
echo ""

echo "================================================"
echo -e "${GREEN}✅ ALL CHECKS PASSED${NC}"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Test in Burp Suite:"
echo "     Extensions → Installed → Add → Select JAR"
echo ""
echo "  2. Create release:"
echo "     git tag v1.2.1"
echo "     git push origin v1.2.1"
echo ""
echo "  3. If Zed IDE shows errors, see ZED_IDE_FIX.md"
echo ""
