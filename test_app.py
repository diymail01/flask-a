#!/usr/bin/env python3
"""
Simple test script to verify the Flask application functionality
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from flask import Flask
        print("✅ Flask imported successfully")
    except ImportError as e:
        print(f"❌ Flask import failed: {e}")
        return False
    
    try:
        import scanner
        print("✅ Scanner module imported successfully")
    except ImportError as e:
        print(f"❌ Scanner import failed: {e}")
        return False
    
    try:
        from scanner import init_db, CHECK_FUNCTIONS
        print("✅ Scanner functions imported successfully")
    except ImportError as e:
        print(f"❌ Scanner functions import failed: {e}")
        return False
    
    return True

def test_database():
    """Test database initialization"""
    print("\nTesting database...")
    
    try:
        from scanner import init_db
        result = init_db()
        print(f"✅ Database initialization: {result}")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def test_check_functions():
    """Test if all check functions are available"""
    print("\nTesting check functions...")
    
    try:
        from scanner import CHECK_FUNCTIONS
        
        # Test a few key functions
        test_functions = [
            'check_open_ports',
            'check_ssh_ports', 
            'check_ftp_ports',
            'check_web_ports',
            'check_management_ports'
        ]
        
        missing_functions = []
        for func_name in test_functions:
            if func_name in CHECK_FUNCTIONS:
                print(f"✅ {func_name} available")
            else:
                print(f"❌ {func_name} missing")
                missing_functions.append(func_name)
        
        if missing_functions:
            print(f"❌ Missing functions: {missing_functions}")
            return False
        else:
            print("✅ All test functions available")
            return True
            
    except Exception as e:
        print(f"❌ Check functions test failed: {e}")
        return False

def test_basic_scan():
    """Test a basic scan function"""
    print("\nTesting basic scan function...")
    
    try:
        from scanner import check_open_ports
        
        # Test with a localhost scan
        result = check_open_ports('127.0.0.1')
        print(f"✅ Basic scan test completed: {result}")
        return True
    except Exception as e:
        print(f"❌ Basic scan test failed: {e}")
        return False

def test_flask_app():
    """Test Flask app creation"""
    print("\nTesting Flask app...")
    
    try:
        from app import app
        print("✅ Flask app created successfully")
        
        # Test basic route
        with app.test_client() as client:
            response = client.get('/')
            print(f"✅ Home route test: {response.status_code}")
            
            response = client.get('/compliance')
            print(f"✅ Compliance route test: {response.status_code}")
            
        return True
    except Exception as e:
        print(f"❌ Flask app test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🔍 Security Compliance Automation - Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_database,
        test_check_functions,
        test_basic_scan,
        test_flask_app
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application should work correctly.")
        return True
    else:
        print("⚠️ Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 