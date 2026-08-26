## Summary

Describe the user-visible outcome and why this change is needed.

## Validation

- [ ] Native tests pass (`make test`)
- [ ] Desktop tests pass (`make java-test`)
- [ ] Portfolio documentation passes (`make portfolio-check`)
- [ ] Security-sensitive changes include adversarial coverage
- [ ] Documentation reflects behavior and limitations

## Security and privacy

- [ ] No credentials, personal paths, private hostnames, or generated audit data are committed
- [ ] Credential values remain excluded from memory, logs, UI, and exports
- [ ] New permissions, data flows, and trust-boundary changes are documented
- [ ] This change does not silently expand enforcement behavior

## Release impact

- [ ] `CHANGELOG.md` is updated when the change is user-visible
- [ ] Packaging and uninstall behavior were considered
