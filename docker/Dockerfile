FROM python:3.11-slim

# No extra packages: agents carry their own code in code/.
# If an agent needs libraries, it should declare them and the node operator
# can extend this image or provide an alternative via manifest.runtime.image.

# Create a non-root user at uid/gid 1000.
# The node writes state/ and history.log on the host with the host user's
# ownership, then bind-mounts them into the container as this user.
# If those paths are not writable by uid 1000, the agent cannot checkpoint.
# See: `python3 -m clawp2p init` — it sets ownership during agent creation.
RUN groupadd -g 1000 agent && useradd -u 1000 -g 1000 -s /bin/false -d /agent agent

# Verify python3.11 resolves — sandbox.py invokes manifest.runtime.interpreter
# directly and the default value is "python3.11", not "python3".
RUN python3.11 --version

WORKDIR /agent
USER 1000:1000
