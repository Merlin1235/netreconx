from engine.scanner.tcp import TCPScanner


def test_scanner_initialization() -> None:
    scanner = TCPScanner(
        target="127.0.0.1",
        timeout=0.5,
    )

    assert scanner.target == "127.0.0.1"
    assert scanner.timeout == 0.5


def test_empty_target_is_rejected() -> None:
    with pytest.raises(ValueError):
        TCPScanner(target="")


def test_invalid_timeout_is_rejected() -> None:
    with pytest.raises(ValueError):
        TCPScanner(
            target="127.0.0.1",
            timeout=0,
        )


def test_invalid_port_is_rejected() -> None:
    scanner = TCPScanner(target="127.0.0.1")

    with pytest.raises(ValueError):
        scanner.scan_port(0)

    with pytest.raises(ValueError):
        scanner.scan_port(65536)
