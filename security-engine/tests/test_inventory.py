"""
Unit tests for deterministic package file inventory generation.
"""

import os
import hashlib
import tempfile
from engine.ingestion.inventory import (
    build_package_inventory,
    detect_file_type_and_binary,
    check_suspicious_filename,
)


def test_detect_file_type_and_binary():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Plain JavaScript
        js_file = os.path.join(tmp_dir, "app.js")
        with open(js_file, "w") as f:
            f.write("console.log('hi');")
        ftype, is_bin = detect_file_type_and_binary(js_file)
        assert ftype == "JAVASCRIPT"
        assert not is_bin

        # 2. Shell Script with shebang
        sh_file = os.path.join(tmp_dir, "install.sh")
        with open(sh_file, "w") as f:
            f.write("#!/bin/bash\necho install")
        ftype, is_bin = detect_file_type_and_binary(sh_file)
        assert ftype == "SHELL_SCRIPT"
        assert not is_bin

        # 3. Simulated ELF binary
        elf_file = os.path.join(tmp_dir, "daemon")
        with open(elf_file, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
        ftype, is_bin = detect_file_type_and_binary(elf_file)
        assert ftype == "ELF_BINARY"
        assert is_bin

        # 4. Simulated Windows PE binary
        pe_file = os.path.join(tmp_dir, "helper.exe")
        with open(pe_file, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 32)
        ftype, is_bin = detect_file_type_and_binary(pe_file)
        assert ftype == "PE_WINDOWS_BINARY"
        assert is_bin


def test_check_suspicious_filename():
    assert check_suspicious_filename("native/libaddon.node")
    assert check_suspicious_filename("bin/worker.exe")
    assert check_suspicious_filename("scripts/run.bat")
    assert check_suspicious_filename("site-packages/hook.pth")  # Python startup hook
    assert check_suspicious_filename(".env")
    assert check_suspicious_filename("config/.env.local")
    assert check_suspicious_filename("scripts/stealth.js.exe")  # Double extension

    # Benign filenames
    assert not check_suspicious_filename("index.js")
    assert not check_suspicious_filename("README.md")
    assert not check_suspicious_filename("package.json")
    assert not check_suspicious_filename("setup.py")


def test_package_inventory_deterministic_and_accurate():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a hierarchy of files
        os.makedirs(os.path.join(tmp_dir, "src"), exist_ok=True)
        os.makedirs(os.path.join(tmp_dir, "bin"), exist_ok=True)

        f1 = os.path.join(tmp_dir, "src", "index.js")
        with open(f1, "w") as f:
            f.write("module.exports = {};")

        f2 = os.path.join(tmp_dir, "package.json")
        with open(f2, "w") as f:
            f.write('{"name": "test"}')

        f3 = os.path.join(tmp_dir, "bin", "binary.node")
        with open(f3, "wb") as f:
            f.write(b"\x00\x01\x02\x03\x04")

        inventory = build_package_inventory(tmp_dir)

        # 1. Total file counts & sizes
        assert inventory.total_files == 3
        assert inventory.binary_file_count == 1
        assert "bin/binary.node" in inventory.suspicious_files

        # 2. Extension distribution
        assert inventory.extension_distribution.get("js") == 1
        assert inventory.extension_distribution.get("json") == 1
        assert inventory.extension_distribution.get("node") == 1

        # 3. Deterministic sorted ordering
        paths = [item.relative_path for item in inventory.files]
        assert paths == ["bin/binary.node", "package.json", "src/index.js"]

        # 4. Hash verification
        expected_json_sha256 = hashlib.sha256(b'{"name": "test"}').hexdigest()
        json_item = [x for x in inventory.files if x.relative_path == "package.json"][0]
        assert json_item.sha256 == expected_json_sha256
        assert not json_item.is_binary
