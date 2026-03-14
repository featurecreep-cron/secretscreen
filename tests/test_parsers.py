"""Tests for structured value parsing (Layer 2)."""


from secretscreen._parsers import extract_pairs


class TestJsonParsing:
    """JSON value extraction."""

    def test_simple_object(self) -> None:
        pairs = extract_pairs('{"host": "localhost", "password": "secret"}')
        keys = [k for k, _ in pairs]
        assert "host" in keys
        assert "password" in keys

    def test_nested_object(self) -> None:
        pairs = extract_pairs('{"db": {"password": "secret"}}')
        keys = [k for k, _ in pairs]
        assert "db.password" in keys

    def test_array_of_objects(self) -> None:
        pairs = extract_pairs('[{"name": "x", "token": "abc"}]')
        keys = [k for k, _ in pairs]
        assert "[0].name" in keys
        assert "[0].token" in keys


class TestPythonLiteralParsing:
    """Python dict/list literal extraction."""

    def test_dict_literal(self) -> None:
        pairs = extract_pairs("{'OAUTH2_CLIENT_SECRET': 'mysecret', 'HOST': 'localhost'}")
        keys = [k for k, _ in pairs]
        assert "OAUTH2_CLIENT_SECRET" in keys

    def test_nested_dict(self) -> None:
        pairs = extract_pairs("{'config': {'password': 'abc'}}")
        keys = [k for k, _ in pairs]
        assert "config.password" in keys


class TestDsnParsing:
    """DSN/connection string extraction."""

    def test_postgres_dsn(self) -> None:
        pairs = extract_pairs("host=localhost port=5432 user=admin password=secret dbname=mydb")
        d = dict(pairs)
        assert d["password"] == "secret"
        assert d["host"] == "localhost"

    def test_sqlserver_dsn(self) -> None:
        pairs = extract_pairs("Server=myhost;Database=mydb;User Id=admin;Password=secret")
        d = dict(pairs)
        assert d["Password"] == "secret"
        assert d["Server"] == "myhost"


class TestUrlQueryParsing:
    """URL query parameter extraction."""

    def test_query_params(self) -> None:
        pairs = extract_pairs("https://example.com/api?token=abc123&user=admin")
        d = dict(pairs)
        assert d["token"] == "abc123"

    def test_url_with_credentials(self) -> None:
        pairs = extract_pairs("https://example.com/api?token=abc123&password=secret")
        d = dict(pairs)
        assert d["password"] == "secret"
        assert d["token"] == "abc123"


class TestIniParsing:
    """INI-style value extraction."""

    def test_ini_content(self) -> None:
        content = "[database]\nhost = localhost\npassword = secret"
        pairs = extract_pairs(content)
        d = dict(pairs)
        assert d["password"] == "secret"


class TestEdgeCases:
    """Parser edge cases."""

    def test_empty_string(self) -> None:
        assert extract_pairs("") == []

    def test_short_string(self) -> None:
        assert extract_pairs("ab") == []

    def test_plain_string(self) -> None:
        assert extract_pairs("just a normal value") == []

    def test_oversized_value(self) -> None:
        """Values over MAX_PARSE_LENGTH are skipped."""
        huge = '{"key": "' + "x" * 70000 + '"}'
        assert extract_pairs(huge) == []

    def test_malformed_json_no_crash(self) -> None:
        """Parser exceptions are suppressed."""
        assert extract_pairs("{broken json") == []

    def test_malformed_python_no_crash(self) -> None:
        assert extract_pairs("{broken': 'python") == []
