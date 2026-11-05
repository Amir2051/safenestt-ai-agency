import pytest
from fastapi import HTTPException
from app.main import _validate_read_only_sql

@pytest.mark.parametrize('sql', [
    'NOT_A_SQL_STATEMENT', 'SELECT FROM', 'SELECT 1; SELECT 2',
    'SELECT 1 INTO created_table', 'EXPLAIN ANALYZE SELECT 1',
    'INSERT INTO audit_events DEFAULT VALUES',
    'UPDATE audit_events SET id = id', 'DELETE FROM audit_events',
    'DROP TABLE audit_events',
    'WITH changed AS (DELETE FROM audit_events RETURNING *) SELECT * FROM changed',
])
def test_rejects_invalid_or_non_read_only_sql(sql):
    with pytest.raises(HTTPException):
        _validate_read_only_sql(sql)

@pytest.mark.parametrize('sql', [
    'SELECT 1', 'SELECT current_database()', 'EXPLAIN SELECT 1',
    'SELECT id FROM audit_events LIMIT 1',
])
def test_accepts_single_read_only_select(sql):
    _validate_read_only_sql(sql)

def test_rejects_empty_statement():
    with pytest.raises(HTTPException) as exc:
        _validate_read_only_sql(' ; ')
    assert exc.value.status_code == 400

def test_invalid_sql_is_rejected_before_database_connection(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main

    def forbidden_connection():
        raise AssertionError('database connection must not be opened for invalid SQL')

    monkeypatch.setattr(main, '_get_conn', forbidden_connection)
    client = TestClient(main.app)
    response = client.post(
        '/v1/ops/query',
        headers={'X-API-Key': main.API_KEY},
        json={'sql': 'NOT_A_SQL_STATEMENT'},
    )
    assert response.status_code == 400
    assert response.json()['detail'] == 'invalid SQL syntax'
