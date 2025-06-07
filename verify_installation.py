#!/usr/bin/env python3
"""
Installation and Entry Point Verification Script
CTF Networks Challenges - Academic Project
"""

import sys
import importlib
import subprocess

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("🔍 Checking Python Dependencies...")
    
    required_packages = [
        'cryptography',
        'OpenSSL',
        'scapy',
        'psutil'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package} (MISSING)")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies are installed!\n")
    return True

def check_entry_points():
    """Verify that all entry points are available."""
    print("🔍 Checking Entry Points...")
    
    entry_points = [
        ('tls.ctf_server', 'CTF Server'),
        ('tls.gui', 'CTF GUI'),
        ('tls.server_challenges.ping_player', 'Ping Player')
    ]
    
    success = True
    
    for module_name, description in entry_points:
        try:
            module = importlib.import_module(module_name)
            if hasattr(module, 'main'):
                print(f"  ✅ {description} ({module_name})")
            else:
                print(f"  ⚠️  {description} - main() function not found")
                success = False
        except ImportError as e:
            print(f"  ❌ {description} - Import failed: {e}")
            success = False
    
    if success:
        print("✅ All entry points are available!\n")
    else:
        print("⚠️  Some entry points have issues.\n")
    
    return success

def check_project_structure():
    """Verify that the project structure is correct."""
    print("🔍 Checking Project Structure...")
    
    import os
    
    required_files = [
        'requirements.txt',
        'setup.py',
        'README.md',
        'tls/ctf_server.py',
        'tls/gui.py',
        'tls/server_challenges/ping_player.py',
        'certificates/',
        'documents/'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path} (MISSING)")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Missing files/directories: {', '.join(missing_files)}")
        return False
    
    print("✅ Project structure is complete!\n")
    return True

def display_usage_guide():
    """Display usage information for participants."""
    print("📖 Usage Guide:")
    print("="*50)
    print("🚀 Running the CTF Server:")
    print("  Command Line: python -m tls.ctf_server")
    print("  GUI Version:  python -m tls.gui")
    print()
    print("🎯 For Participants:")
    print("  1. Read the README.md for complete instructions")
    print("  2. Install required tools: Wireshark, Burp Suite, OpenSSL")
    print("  3. Ensure admin/root privileges for ICMP challenges")
    print("  4. Follow the challenge stages sequentially")
    print()
    print("📚 Academic Submission:")
    print("  - Refer to Hebrew guidelines in README.md")
    print("  - Document all steps with screenshots")
    print("  - Include technical analysis and learning outcomes")
    print("="*50)

def main():
    """Main verification function."""
    print("🎓 CTF Networks Challenges - Installation Verification")
    print("="*60)
    print("Academic Project: Advanced Computer Networks")
    print("Institution: Sharif University of Technology")
    print("="*60)
    print()
    
    # Run all checks
    dependencies_ok = check_dependencies()
    entry_points_ok = check_entry_points()
    structure_ok = check_project_structure()
    
    # Final status
    if dependencies_ok and entry_points_ok and structure_ok:
        print("🎉 VERIFICATION SUCCESSFUL!")
        print("✅ The CTF is ready to run!")
        print()
        display_usage_guide()
        return 0
    else:
        print("❌ VERIFICATION FAILED!")
        print("⚠️  Please resolve the issues above before proceeding.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
