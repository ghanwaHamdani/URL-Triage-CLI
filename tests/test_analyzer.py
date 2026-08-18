from triage.triage_analyzer import URLAnalyzer


def test_ip_detection():
    analyzer = URLAnalyzer("http://192.168.1.1/login.php")
    report = analyzer.analyze()

    # assert score is at least 40 and level is medium or high
    assert report["score"] >= 40
    assert "HIGH / CRITICAL" in report["risk_level"] or "MEDIUM" in report["risk_level"]

def test_sus_tld():
    analyzer = URLAnalyzer("http://secure-verify.xyz")
    report = analyzer.analyze()

    # assert .xys warning wxists in report warnings    
    assert any(".xyz" in w for w in report["warnings"])