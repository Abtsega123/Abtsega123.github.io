"""Top-level discovery wrapper so GitHub Actions can run all project tests."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

def load_tests(loader, tests, pattern):
    suite=unittest.TestSuite()
    for path in sorted((ROOT/'projects').glob('*/tests/test_*.py')):
        spec=importlib.util.spec_from_file_location('portfolio_'+path.parent.parent.name.replace('-','_'),path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite
