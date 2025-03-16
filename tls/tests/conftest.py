import pytest

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "unit: mark a test as a unit test."
    )
