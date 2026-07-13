# Security Policy

## Sensitive data

Never attach authentication JSON, access tokens, refresh tokens, session
tokens, API keys, management keys, or unredacted runtime logs to a public
issue.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this
repository. Include reproducible steps and sanitized logs. If private
reporting is unavailable, open a minimal issue that contains no credentials
and ask the maintainer for a private contact channel.

## Deployment guidance

- Bind the inspector to localhost unless you add an authentication layer.
- Mount only the intended authentication directory.
- Back up credentials before enabling refresh or batch status changes.
- Keep CLIProxyAPI and this plugin updated together because the native ABI may
  evolve.
