from build_doctor.redact import Redactor, sanitize_url, scrub_secrets


def test_url_credentials_and_query():
    assert (
        sanitize_url("https://u:p@example.com/a?token=1")
        == "https://***@example.com/a?***"
    )


def test_secret_patterns():
    assert "hunter2" not in scrub_secrets("password=hunter2")
    assert "ghp_" not in scrub_secrets("x ghp_" + "a" * 36)


def test_path_placeholders(tmp_path):
    r = Redactor(str(tmp_path / "proj"))
    assert r.text(f"{tmp_path}/proj/src/A.cs") == "<PROJECT>/src/A.cs"
    assert (
        Redactor(str(tmp_path), show_paths=True).text(f"{tmp_path}/x")
        == f"{tmp_path}/x"
    )
