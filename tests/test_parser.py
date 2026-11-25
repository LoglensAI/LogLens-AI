import pytest

from loglens.detection.parser import detect_format, infer_level, parse_line

# --- original format tests ---


def test_detect_standard_format():
    line = "2024-01-15T10:00:00Z INFO [nginx] GET /api 200"
    assert detect_format(line) == "STANDARD"


def test_detect_json_format():
    line = '{"timestamp": "2024-01-15", "level": "ERROR", "message": "timeout"}'
    assert detect_format(line) == "JSON"


def test_detect_nginx_format():
    line = '192.168.1.1 - - [15/Jan/2024:10:00:00 +0000] "GET /api 200" 200 1240'
    assert detect_format(line) == "NGINX"


def test_detect_plaintext_format():
    line = "something went wrong unexpectedly"
    assert detect_format(line) == "PLAINTEXT"


def test_malformed_line_returns_none():
    assert parse_line("", "STANDARD") is None


def test_logentry_dataclass_fields():
    line = "2024-01-15T10:00:00Z ERROR [payment-service] DB timeout"
    entry = parse_line(line, "STANDARD")
    assert entry is not None
    assert entry.level == "ERROR"
    assert entry.service == "payment-service"
    assert entry.message == "DB timeout"


def test_json_parse():
    line = '{"timestamp": "2024-01-15", "level": "error", "service": "auth", "message": "token expired"}'
    entry = parse_line(line, "JSON")
    assert entry is not None
    assert entry.level == "ERROR"
    assert entry.service == "auth"


# --- Stage 1: new format detection + parsing ---


@pytest.mark.parametrize(
    "line,fmt,level,service",
    [
        (
            "2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster",
            "APP_LOG",
            "INFO",
            "org.apache.hadoop.mapreduce.v2.app.MRAppMaster",
        ),
        (
            "2015-07-29 17:41:41,536 - INFO  [main:QuorumPeerConfig@103] - Reading configuration",
            "ZK_LOG",
            "INFO",
            "zookeeper",
        ),
        (
            "17/06/09 20:10:40 INFO executor.Executor: Running task 0.0",
            "SPARK_LOG",
            "INFO",
            "executor.Executor",
        ),
        (
            "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok",
            "APACHE_ERR",
            "NOTICE",
            "apache",
        ),
        (
            "2016-09-28 04:30:30, Info CBS Loaded Servicing Stack v6.1.7601.23505",
            "WINCBS",
            "INFO",
            "CBS",
        ),
        (
            "- 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 2005-06-03-15.42.50.363779 R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error",
            "HPC",
            "INFO",
            "R02-M1-N0-C:J12-U11",
        ),
        (
            "20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579",
            "HEALTHAPP",
            "INFO",
            "Step_LSC",
        ),
        (
            "[10.30 16:49:06] chrome.exe - proxy.cse.cuhk.edu.hk:5070 open through proxy",
            "PROXIFIER",
            "INFO",
            "chrome.exe",
        ),
        (
            "[10.30 17:59:17] svchost.exe *64 - proxy close, 303 bytes sent",
            "PROXIFIER",
            "INFO",
            "svchost.exe *64",
        ),
    ],
)
def test_new_format_detect_and_parse(line, fmt, level, service):
    assert detect_format(line) == fmt
    entry = parse_line(line, fmt)
    assert entry is not None and entry.parsed
    assert entry.level == level
    assert entry.service == service


@pytest.mark.parametrize(
    "text,expected",
    [
        ("segfault detected FATAL abort", "CRITICAL"),
        ("connection ERROR refused", "ERROR"),
        ("task WARNING slow response", "WARN"),
        ("user login successful", "INFO"),
    ],
)
def test_infer_level(text, expected):
    assert infer_level(text) == expected


def test_hpc_alert_label_in_metadata():
    line = (
        "KERNEL_ISSUE 1117838570 2005.06.03 R02-M1 "
        "2005-06-03-15.42.50 R02-M1 RAS KERNEL FATAL panic"
    )
    entry = parse_line(line, "HPC")
    assert entry.metadata["alert_label"] == "KERNEL_ISSUE"
    assert entry.level == "CRITICAL"


@pytest.mark.parametrize(
    "line,provider,level,service",
    [
        (
            '{"eventTime":"2024-01-15T10:00:00Z","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4","errorMessage":"Failed authentication"}',
            "AWS",
            "ERROR",
            "signin",
        ),
        (
            '{"eventTime":"2024-01-15T10:01:00Z","eventName":"RunInstances","eventSource":"ec2.amazonaws.com","awsRegion":"ap-south-1","sourceIPAddress":"5.6.7.8"}',
            "AWS",
            "INFO",
            "ec2",
        ),
        (
            '{"timestamp":"2024-01-15T10:00:00Z","severity":"ERROR","resource":{"type":"gce_instance"},"logName":"projects/x/logs/syslog","textPayload":"OOM killer invoked"}',
            "GCP",
            "ERROR",
            "gce_instance",
        ),
        (
            '{"timestamp":"2024-01-15T10:02:00Z","severity":"WARNING","resource":{"type":"k8s_container"},"jsonPayload":{"message":"pod restart"}}',
            "GCP",
            "WARN",
            "k8s_container",
        ),
        (
            '{"time":"2024-01-15T10:00:00Z","resourceId":"/SUBS/x/vm1","operationName":"Microsoft.Compute/virtualMachines/write","level":"Error","category":"Administrative","properties":{"statusMessage":"deployment failed"}}',
            "AZURE",
            "ERROR",
            "Administrative",
        ),
    ],
)
def test_cloud_json_mapping(line, provider, level, service):
    entry = parse_line(line, "JSON")
    assert entry is not None and entry.parsed
    assert entry.metadata["provider"] == provider
    assert entry.level == level
    assert entry.service == service


def test_plain_json_still_works():
    line = '{"timestamp":"2024-01-15","level":"error","service":"auth","message":"token expired"}'
    entry = parse_line(line, "JSON")
    assert entry.service == "auth"
    assert entry.level == "ERROR"
    assert "provider" not in entry.metadata


# --- crash lines without a level, and exception lines in stack traces ---------


def test_levelless_crash_lines_are_critical():
    from loglens.detection.parser import infer_level

    for text in (
        "Out of memory: Killed process 4242 (java)",
        "Segmentation fault (core dumped)",
        "kernel: BUG: soft lockup - watchdog timeout",
        "invoked oom-killer: gfp_mask=0x100cca",
    ):
        assert infer_level(text) == "CRITICAL", text
    assert infer_level("worker ready") == "INFO"
    assert infer_level("WARN disk at 80%") == "WARN"  # explicit level still wins


def test_python_exception_line_stays_with_its_traceback():
    from loglens.detection.parser import StreamParser

    lines = [
        "2026-01-01 10:00:00 INFO app: ok",
        "2026-01-01 10:01:00 ERROR app: crash",
        "Traceback (most recent call last):",
        '  File "app.py", line 3, in <module>',
        "    main()",
        "ZeroDivisionError: division by zero",
        "2026-01-01 10:02:00 INFO app: recovered",
    ]
    es = list(StreamParser().parse_all(lines))
    assert [e.level for e in es] == ["INFO", "ERROR", "INFO"]
    assert "ZeroDivisionError: division by zero" in es[1].message


def test_java_exception_header_stays_with_its_error():
    from loglens.detection.parser import StreamParser

    lines = [
        "2026-01-01 10:02:00,001 ERROR [main] c.e.App - Unhandled exception",
        "java.lang.NullPointerException: user is null",
        "\tat com.example.Service.get(Service.java:42)",
        "Caused by: java.io.IOException: boom",
        "\t... 3 more",
        "2026-01-01 10:02:01,000 INFO  [main] c.e.App - next",
    ]
    es = list(StreamParser().parse_all(lines))
    assert len(es) == 2
    assert es[0].level == "ERROR" and "NullPointerException" in es[0].message
