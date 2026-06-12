# Fluidra Local Bridge

Runs the Fluidra Local Bridge inside Home Assistant.

Configure this add-on with your Fluidra backend credentials/refresh token and an optional local `auth_token`. Then configure the HACS integration `Roagert/ha-fluidra-local` v0.3.0+ to point at this bridge URL and the same token.

This is a local bridge with a cloud REST backend today, not proven direct LAN control of stock Fluidra firmware.
