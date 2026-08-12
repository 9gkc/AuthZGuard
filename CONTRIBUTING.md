# Contributing

Contributions are welcome when they keep AuthZGuard focused on authorized, low-impact authorization regression testing.

Before opening a pull request, add or update tests, run `python -m unittest discover -s tests -v`, avoid live targets in fixtures or documentation, and ensure no token, target, or response body is committed. Changes that add unsafe methods, automatic discovery, credential acquisition, response-body collection, or public-target defaults will not be accepted.

