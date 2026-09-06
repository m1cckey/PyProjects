from AuditDeps import AuditScanner
import pytest
import time

scanner = AuditScanner('test_req.txt', 'test_cache.json')


def test_load_cache():
    scanner.load_cache()
    assert scanner.cache == {"qazwsx": "654321"}
    assert not scanner.cache == {}

def test_create_pack():
    scanner.create_pack()
    assert scanner.pack[0] == ('pytest', '9.1.1')
    assert scanner.pack[-1] == ('python', '3.14.0')
    assert scanner.pack[1] == ('gjango', '9.0.0')


def test_write_cache():
    scanner.cache = {"qazwsx": "654321"}
    scanner.write_cache()
    with open('test_cache.json', 'r') as file:
        cache = file.read()
        
    assert cache == '{\n    "qazwsx": "654321"\n}'



