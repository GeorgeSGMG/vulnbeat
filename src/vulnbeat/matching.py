from vulnbeat.models import Component, Finding, Vulnerability


def match(app_id: str, components: dict[str, Component], vulnerabilities: list[Vulnerability]) -> list[Finding]:
    findings = []
    for vulnerability in vulnerabilities:
        product = vulnerability.product.lower()
        for package_name, component in components.items():
            if package_name and package_name in product:
                findings.append(
                    Finding(
                        app_id=app_id,
                        package_name=package_name,
                        component=component,
                        vulnerability=vulnerability,
                    )
                )
    return findings