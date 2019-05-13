# csbootstrap

## Usage

- Install csbootstrap using pip: `pip install csbootstrap --user`.
- Download the `bootstrap.json` file for your device from the onboarding dialog in CENTERSIGHT NG.
- Run `csbootstrap --bootstrap-info bootstrap.json`.

The last two steps can be combined like this:

```sh
curl -X POST "https://$SUBDOMAIN.centersightcloud.com/api/beta/gateways/urn/$URN/bootstrap.json" \
  -u "$USER:$PW" -s \
  | csbootstrap
```

Where `URN` is the URN of your device and `SUBDOMAIN` is the subdomain of your organization.

A new certificate can be requested by using the `renew` command.

To get an overview of all options run `csbootstrap -h`.

## Development

This repository requires Python 3. Dependencies can be installed using
`pip`:

```
pip install -r requirements.txt --user
```
